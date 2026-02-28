"""Push orchestrator for queue-driven batch operations across managed devices.

Replaces the fire-and-forget PushEngine with a persistent queue-based approach
that supports batching, per-device locking, controlled concurrency, and retries.
"""

import json
import logging
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Dict, List

from database import get_db
from services.rules_engine import _write_audit_log

logger = logging.getLogger(__name__)

# Operations sitting in 'in_progress' longer than this are considered stale
STALE_THRESHOLD_MINUTES = 10

# Alias name used by the floating rule approach on pfSense devices
PFSENSE_ALIAS_NAME = "soc_blocklist"


def _create_pfsense_client(device: dict):
    """Factory function for PfSenseClient."""
    from clients.pfsense_client import PfSenseClient
    return PfSenseClient(
        host=device["hostname"],
        username=device["web_username"],
        password=device["web_password"],
        verify_ssl=False,
        block_method=device.get("block_method", "null_route"),
    )


def _create_linux_client(device: dict):
    """Factory function for LinuxClient."""
    from clients.linux_client import LinuxClient
    return LinuxClient(
        host=device["hostname"],
        port=device.get("ssh_port", 22) or 22,
        username=device.get("ssh_username", ""),
        password=device.get("ssh_password"),
        key_path=device.get("ssh_key_path"),
        key_content=device.get("ssh_key"),
        sudo_password=device.get("sudo_password"),
    )


def _create_cisco_ios_client(device: dict):
    """Factory function for CiscoIOSClient."""
    from clients.cisco_ios_client import CiscoIOSClient
    return CiscoIOSClient(
        host=device["hostname"],
        port=device.get("ssh_port", 22),
        username=device["ssh_username"],
        password=device["ssh_password"],
        enable_password=device.get("enable_password", ""),
        acl_name=device.get("group_name", "SOC_BLOCKLIST"),
    )


def _create_cisco_asa_client(device: dict):
    """Factory function for CiscoASAClient."""
    from clients.cisco_asa_client import CiscoASAClient
    return CiscoASAClient(
        host=device["hostname"],
        port=device.get("ssh_port", 22),
        username=device["ssh_username"],
        password=device["ssh_password"],
        enable_password=device.get("enable_password", ""),
        object_group_name=device.get("group_name", "SOC_BLOCKLIST"),
    )


def _create_fortinet_client(device: dict):
    """Factory function for FortinetClient."""
    from clients.fortinet_client import FortinetClient
    return FortinetClient(
        host=device["hostname"],
        port=device.get("ssh_port", 22),
        username=device["ssh_username"],
        password=device["ssh_password"],
        address_group_name=device.get("group_name", "SOC_BLOCKLIST"),
    )


def _create_palo_alto_client(device: dict):
    """Factory function for PaloAltoClient."""
    from clients.palo_alto_client import PaloAltoClient
    return PaloAltoClient(
        host=device["hostname"],
        port=device.get("ssh_port", 22),
        username=device["ssh_username"],
        password=device["ssh_password"],
        address_group_name=device.get("group_name", "SOC_BLOCKLIST"),
    )


def _create_unifi_client(device: dict):
    """Factory function for UniFiClient."""
    from clients.unifi_client import UniFiClient
    return UniFiClient(
        host=device["hostname"],
        api_port=device.get("api_port", 443),
        username=device["ssh_username"],
        password=device["ssh_password"],
        network_list_name=device.get("group_name", "SOC_BLOCKLIST"),
    )


def _create_aws_waf_client(device: dict):
    """Factory function for AwsWafClient."""
    from clients.aws_waf_client import AwsWafClient
    creds = json.loads(device.get("cloud_credentials", "{}"))
    return AwsWafClient(
        access_key=creds["access_key"],
        secret_key=creds["secret_key"],
        region=device["cloud_region"],
        ip_set_name=device["cloud_resource_id"],
        ip_set_scope=creds.get("ip_set_scope", "REGIONAL"),
    )


def _create_azure_nsg_client(device: dict):
    """Factory function for AzureNsgClient."""
    from clients.azure_nsg_client import AzureNsgClient
    creds = json.loads(device.get("cloud_credentials", "{}"))
    return AzureNsgClient(
        tenant_id=creds["tenant_id"],
        client_id=creds["client_id"],
        client_secret=creds["client_secret"],
        subscription_id=creds["subscription_id"],
        resource_group=creds["resource_group"],
        nsg_name=device["cloud_resource_id"],
    )


def _create_gcp_firewall_client(device: dict):
    """Factory function for GcpFirewallClient."""
    from clients.gcp_firewall_client import GcpFirewallClient
    creds = json.loads(device.get("cloud_credentials", "{}"))
    return GcpFirewallClient(
        service_account_json=creds["service_account_json"],
        project_id=device["cloud_resource_id"],
        network_name=creds.get("network_name", "default"),
    )


def _create_oci_nsg_client(device: dict):
    """Factory function for OciNsgClient."""
    from clients.oci_nsg_client import OciNsgClient
    creds = json.loads(device.get("cloud_credentials", "{}"))
    return OciNsgClient(
        tenancy_ocid=creds["tenancy_ocid"],
        user_ocid=creds["user_ocid"],
        api_key_pem=creds["api_key_pem"],
        fingerprint=creds["fingerprint"],
        region=device["cloud_region"],
        nsg_ocid=device["cloud_resource_id"],
    )



# Registry mapping device_type strings to client factory functions.
# To add a new vendor: create a client in clients/, add a factory here.
CLIENT_REGISTRY = {
    "pfsense": _create_pfsense_client,
    "linux": _create_linux_client,
    "cisco_ios": _create_cisco_ios_client,
    "cisco_asa": _create_cisco_asa_client,
    "fortinet": _create_fortinet_client,
    "palo_alto": _create_palo_alto_client,
    "unifi": _create_unifi_client,
    "aws_waf": _create_aws_waf_client,
    "azure_nsg": _create_azure_nsg_client,
    "gcp_firewall": _create_gcp_firewall_client,
    "oci_nsg": _create_oci_nsg_client,
}

# Maximum IPs to send per add_rules_bulk / remove_rules_bulk call.
# Cloud providers have hard capacity limits; sending more than the limit
# in one call causes the client to immediately fail the overflow IPs.
# Chunking at the orchestrator level lets the client make real API calls
# for each batch and re-check capacity between batches.
# On-prem types default to 0 (no chunking — send all at once).
DEVICE_BATCH_SIZE = {
    "aws_waf": 500,
    "azure_nsg": 200,
    "gcp_firewall": 200,
    "oci_nsg": 50,
}


class PushOrchestrator:
    """Reads from the operation queue, groups by device, and dispatches batches."""

    def __init__(self, db_path=None, max_concurrency: int = 10):
        self.db_path = db_path
        self.max_concurrency = max_concurrency
        self._device_locks = {}  # type: Dict[int, threading.Lock]

    def _get_device_lock(self, device_id: int) -> threading.Lock:
        """Return (and lazily create) a per-device lock."""
        if device_id not in self._device_locks:
            self._device_locks[device_id] = threading.Lock()
        return self._device_locks[device_id]

    def _read_concurrency_limit(self) -> int:
        """Read concurrency_limit from app_settings, fall back to self.max_concurrency."""
        try:
            with get_db(self.db_path) as conn:
                row = conn.execute(
                    "SELECT concurrency_limit FROM app_settings LIMIT 1"
                ).fetchone()
                if row and row["concurrency_limit"] is not None:
                    val = int(row["concurrency_limit"])
                    if 1 <= val <= 50:
                        return val
        except Exception:
            logger.debug("Could not read concurrency_limit from app_settings, using default")
        return self.max_concurrency


    def process_pending_operations(self) -> None:
        """Main loop: reset stale ops, read pending/retryable ops, group by device, dispatch concurrently."""
        self._reset_stale_operations()

        operations = self._fetch_actionable_operations()
        if not operations:
            return

        concurrency = self._read_concurrency_limit()

        # Group operations by device_id
        by_device = defaultdict(list)  # type: Dict[int, List[dict]]
        for op in operations:
            by_device[op["device_id"]].append(op)

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {
                executor.submit(self.dispatch_batch, device_id, ops): device_id
                for device_id, ops in by_device.items()
            }
            for future in as_completed(futures):
                device_id = futures[future]
                try:
                    future.result()
                except Exception:
                    logger.exception("Unhandled error dispatching to device %d", device_id)

    def _reset_stale_operations(self) -> None:
        """Reset operations stuck in 'in_progress' for longer than the stale threshold."""
        cutoff = datetime.utcnow() - timedelta(minutes=STALE_THRESHOLD_MINUTES)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        with get_db(self.db_path) as conn:
            updated = conn.execute(
                """UPDATE operation_queue
                   SET status = 'pending', started_at = NULL
                   WHERE status = 'in_progress'
                     AND started_at <= ?""",
                (cutoff_str,),
            ).rowcount
            if updated:
                logger.info("Reset %d stale in_progress operations to pending", updated)

    def _fetch_actionable_operations(self) -> List[dict]:
        """Fetch operations that are pending or eligible for retry."""
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        with get_db(self.db_path) as conn:
            rows = conn.execute(
                """SELECT id, operation_id, device_id, action, ip_addresses,
                          status, attempt_count, max_attempts, next_retry_at,
                          error_message, created_at, started_at, completed_at, source
                   FROM operation_queue
                   WHERE status = 'pending'
                      OR (status = 'failed'
                          AND attempt_count < max_attempts
                          AND (next_retry_at IS NULL OR next_retry_at <= ?))
                   ORDER BY created_at ASC""",
                (now_str,),
            ).fetchall()
            return [dict(row) for row in rows]

    def dispatch_batch(self, device_id: int, operations: List[dict]) -> List[dict]:
        """Execute a batch of operations on a single device.

        Acquires per-device lock, marks operations in_progress, executes each
        via _execute_on_device, and updates statuses accordingly.

        Returns list of result dicts from _execute_on_device.
        """
        lock = self._get_device_lock(device_id)
        results = []

        with lock:
            # Look up the device
            with get_db(self.db_path) as conn:
                device = conn.execute(
                    "SELECT * FROM managed_devices WHERE id = ?", (device_id,)
                ).fetchone()

            if not device:
                logger.error("Device %d not found, skipping batch", device_id)
                return results

            device = dict(device)
            now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

            # Mark all operations as in_progress
            op_ids = [op["id"] for op in operations]
            # Filter out operations that were cancelled while queued
            with get_db(self.db_path) as conn:
                placeholders = ",".join("?" for _ in op_ids)
                cancelled_rows = conn.execute(
                    f"SELECT id FROM operation_queue WHERE id IN ({placeholders}) AND status = 'cancelled'",
                    op_ids,
                ).fetchall()
                cancelled_ids = {r["id"] for r in cancelled_rows}

            if cancelled_ids:
                operations = [op for op in operations if op["id"] not in cancelled_ids]
                op_ids = [op["id"] for op in operations]
                if not operations:
                    return results

            with get_db(self.db_path) as conn:
                placeholders = ",".join("?" for _ in op_ids)
                conn.execute(
                    f"""UPDATE operation_queue
                        SET status = 'in_progress', started_at = ?
                        WHERE id IN ({placeholders}) AND status != 'cancelled'""",
                    [now_str] + op_ids,
                )

                # Update push_statuses to in_progress for all IPs in these operations
                for op in operations:
                    ip_list = json.loads(op["ip_addresses"])
                    for ip in ip_list:
                        conn.execute(
                            """UPDATE push_statuses SET status = 'in_progress', pushed_at = ?
                               WHERE device_id = ?
                                 AND block_entry_id IN (
                                     SELECT id FROM block_entries WHERE ip_address = ?
                                 )""",
                            (now_str, device_id, ip),
                        )

            # Execute each operation
            for op in operations:
                ip_list = json.loads(op["ip_addresses"])
                action = op["action"]

                try:
                    result = self._execute_on_device(device, action, ip_list)
                    results.append(result)

                    completed_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

                    succeeded_ips = set(result.get("succeeded_ips", []))
                    skipped_ips = set(result.get("skipped_ips", []))
                    failed_ips = set(result.get("failed_ips", []))
                    has_any_success = len(succeeded_ips) > 0 or len(skipped_ips) > 0

                    # When succeeded_ips/skipped_ips aren't provided (e.g. old
                    # clients), infer from the ip_list minus failed_ips.
                    if not succeeded_ips and not skipped_ips and result["success"]:
                        succeeded_ips = set(ip_list) - failed_ips
                        has_any_success = len(succeeded_ips) > 0

                    if result["success"] or has_any_success:
                        # Update per-IP push_statuses individually regardless
                        # of whether the operation is fully or partially done.
                        with get_db(self.db_path) as conn:
                            # Mark succeeded and skipped IPs as success
                            for ip in ip_list:
                                if ip in succeeded_ips or ip in skipped_ips:
                                    conn.execute(
                                        """UPDATE push_statuses
                                           SET status = 'success', pushed_at = ?, error_message = NULL
                                           WHERE device_id = ?
                                             AND block_entry_id IN (
                                                 SELECT id FROM block_entries WHERE ip_address = ?
                                             )""",
                                        (completed_str, device_id, ip),
                                    )
                            # Mark failed IPs individually
                            error_msg = result.get("error_message", "Push failed")
                            for ip in failed_ips:
                                conn.execute(
                                    """UPDATE push_statuses
                                       SET status = 'failed', pushed_at = ?,
                                           error_message = ?
                                       WHERE device_id = ?
                                         AND block_entry_id IN (
                                             SELECT id FROM block_entries WHERE ip_address = ?
                                         )""",
                                    (completed_str, error_msg, device_id, ip),
                                )

                        if failed_ips:
                            # Partial success — some IPs failed.  Mark the
                            # operation as *failed* so the dashboard does NOT
                            # show a green "completed" when most IPs were
                            # rejected (e.g. cloud device capacity limit).
                            # The per-IP push_statuses above already
                            # record which IPs actually succeeded.
                            partial_msg = (
                                f"Partial: {len(succeeded_ips)} succeeded, "
                                f"{len(skipped_ips)} skipped, "
                                f"{len(failed_ips)} failed — {error_msg}"
                            )
                            self.handle_failure(op["id"], partial_msg)
                        else:
                            # Full success — every IP succeeded or was skipped.
                            with get_db(self.db_path) as conn:
                                conn.execute(
                                    """UPDATE operation_queue
                                       SET status = 'completed', completed_at = ?
                                       WHERE id = ?""",
                                    (completed_str, op["id"]),
                                )

                        # If this was a decommission removal, check if the device
                        # should be deleted now.  Only trigger for decommission
                        # operations — regular API removals must NOT delete the device.
                        if action == "remove" and op.get("source") == "decommission":
                            self._maybe_delete_device_after_cleanup(device_id, device)

                        log_action = f"push {action} completed"
                        if failed_ips:
                            log_action = f"push {action} partial"
                        _write_audit_log(
                            self.db_path,
                            event_type="push",
                            action=log_action,
                            device_id=device_id,
                            operation_id=op.get("operation_id"),
                            details={
                                "success": result["success"],
                                "ip_count": len(ip_list),
                                "succeeded": len(succeeded_ips),
                                "skipped": len(skipped_ips),
                                "failed": len(failed_ips),
                            },
                        )
                    else:
                        # Total failure — no IPs succeeded at all
                        error_msg = result.get("error_message", "Unknown error")
                        self.handle_failure(op["id"], error_msg)

                        # Update push_statuses to failed
                        with get_db(self.db_path) as conn:
                            for ip in ip_list:
                                conn.execute(
                                    """UPDATE push_statuses
                                       SET status = 'failed', pushed_at = ?,
                                           error_message = ?
                                       WHERE device_id = ?
                                         AND block_entry_id IN (
                                             SELECT id FROM block_entries WHERE ip_address = ?
                                         )""",
                                    (completed_str, error_msg, device_id, ip),
                                )

                        _write_audit_log(
                            self.db_path,
                            event_type="push",
                            action=f"push {action} failed",
                            device_id=device_id,
                            operation_id=op.get("operation_id"),
                            details={"success": False, "error": error_msg,
                                     "ip_count": len(ip_list)},
                        )

                except Exception as exc:
                    logger.exception(
                        "Unexpected error executing operation %d on device %d",
                        op["id"], device_id,
                    )
                    error_msg = str(exc)
                    completed_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                    self.handle_failure(op["id"], error_msg)

                    # Update push_statuses to failed
                    with get_db(self.db_path) as conn:
                        for ip in ip_list:
                            conn.execute(
                                """UPDATE push_statuses
                                   SET status = 'failed', pushed_at = ?,
                                       error_message = ?
                                   WHERE device_id = ?
                                     AND block_entry_id IN (
                                         SELECT id FROM block_entries WHERE ip_address = ?
                                     )""",
                                (completed_str, error_msg, device_id, ip),
                            )

                    _write_audit_log(
                        self.db_path,
                        event_type="push",
                        action=f"push {action} error",
                        device_id=device_id,
                        operation_id=op.get("operation_id"),
                        details={"success": False, "error": error_msg,
                                 "ip_count": len(ip_list)},
                    )

                    results.append({
                        "device_id": device_id,
                        "success": False,
                        "failed_ips": ip_list,
                        "error_message": error_msg,
                    })

        return results
    def _execute_on_device(self, device: dict, action: str, ip_addresses: List[str]) -> dict:
        """Execute a batch add/remove on a single device via the appropriate client.

        Uses CLIENT_REGISTRY to look up the client factory by device_type.
        For device types with a DEVICE_BATCH_SIZE entry, IPs are chunked
        into smaller batches so the client can make real API calls per
        chunk and re-check capacity between chunks.

        Returns:
            dict with keys: device_id, success, failed_ips, succeeded_ips,
            skipped_ips, error_message.  ``success`` is True when every IP
            either succeeded or was skipped (i.e. no failures at all).
        """
        device_id = device["id"]
        device_type = device["device_type"]

        try:
            factory = CLIENT_REGISTRY.get(device_type)
            if factory is None:
                return {
                    "device_id": device_id,
                    "success": False,
                    "failed_ips": ip_addresses,
                    "succeeded_ips": [],
                    "skipped_ips": [],
                    "error_message": f"Unsupported device type: {device_type}",
                }

            client = factory(device)

            batch_size = DEVICE_BATCH_SIZE.get(device_type, 0)

            if batch_size and len(ip_addresses) > batch_size:
                # Chunk IPs and merge results across batches
                all_succeeded = []
                all_failed = []
                all_skipped = []

                for i in range(0, len(ip_addresses), batch_size):
                    chunk = ip_addresses[i:i + batch_size]
                    if action == "add":
                        result = client.add_rules_bulk(chunk)
                    else:
                        result = client.remove_rules_bulk(chunk)

                    all_succeeded.extend(result.get("success", []))
                    all_skipped.extend(result.get("skipped", []))
                    chunk_failed = result.get("failed", [])
                    all_failed.extend(chunk_failed)

                    # If the entire chunk failed (e.g. capacity full),
                    # fail all remaining IPs immediately to avoid
                    # pointless API calls.
                    if len(chunk_failed) == len(chunk) and i + batch_size < len(ip_addresses):
                        remaining = ip_addresses[i + batch_size:]
                        for ip in remaining:
                            all_failed.append({"ip": ip, "error": "Skipped — device at capacity"})
                        break

                failed_ips = [f["ip"] if isinstance(f, dict) else f for f in all_failed]
                succeeded_ips = list(all_succeeded)
                skipped_ips = list(all_skipped)
            else:
                # Single call — no chunking needed
                if action == "add":
                    result = client.add_rules_bulk(ip_addresses)
                else:
                    result = client.remove_rules_bulk(ip_addresses)

                failed_ips = [f["ip"] if isinstance(f, dict) else f
                              for f in result.get("failed", [])]
                succeeded_ips = list(result.get("success", []))
                skipped_ips = list(result.get("skipped", []))

            success = len(failed_ips) == 0

            return {
                "device_id": device_id,
                "success": success,
                "failed_ips": failed_ips,
                "succeeded_ips": succeeded_ips,
                "skipped_ips": skipped_ips,
                "error_message": None if success else f"{len(failed_ips)} IPs failed on {device_type} device",
            }

        except Exception as exc:
            logger.exception(
                "Error executing %s on device %d (%s)", action, device_id, device_type
            )
            return {
                "device_id": device_id,
                "success": False,
                "failed_ips": ip_addresses,
                "succeeded_ips": [],
                "skipped_ips": [],
                "error_message": str(exc),
            }

    def handle_failure(self, operation_id: int, error: str) -> None:
        """Handle a failed operation: apply retry with backoff or mark permanently failed.

        Auth/config errors are marked as permanently failed immediately (no retry).
        Otherwise, increment attempt_count and schedule retry with exponential backoff,
        or mark permanently failed if max attempts exhausted.

        Args:
            operation_id: The row id (integer) from operation_queue table.
            error: The error message string.
        """
        # Keywords indicating auth or config errors that should not be retried
        auth_keywords = [
            "authentication", "auth fail", "login fail",
            "401", "403", "permission denied", "invalid config",
            "capacity limit reached", "networkaclentry",
        ]
        error_lower = error.lower() if error else ""
        is_auth_error = any(kw in error_lower for kw in auth_keywords)

        with get_db(self.db_path) as conn:
            row = conn.execute(
                """SELECT id, attempt_count, max_attempts
                   FROM operation_queue WHERE id = ?""",
                (operation_id,),
            ).fetchone()

            if not row:
                logger.warning("handle_failure: operation %d not found", operation_id)
                return

            attempt_count = row["attempt_count"]
            max_attempts = row["max_attempts"]
            now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

            if is_auth_error:
                # Permanently failed — do NOT increment attempt_count
                conn.execute(
                    """UPDATE operation_queue
                       SET status = 'failed', error_message = ?, completed_at = ?
                       WHERE id = ?""",
                    (error, now_str, operation_id),
                )
                logger.info(
                    "Operation %d permanently failed (auth/config error): %s",
                    operation_id, error,
                )
                return

            # Increment attempt count
            attempt_count += 1

            if attempt_count >= max_attempts:
                # Exhausted retries — permanently failed
                conn.execute(
                    """UPDATE operation_queue
                       SET status = 'failed', attempt_count = ?,
                           error_message = ?, completed_at = ?
                       WHERE id = ?""",
                    (attempt_count, error, now_str, operation_id),
                )
                logger.info(
                    "Operation %d permanently failed after %d attempts: %s",
                    operation_id, attempt_count, error,
                )
            else:
                # Schedule retry with exponential backoff: base * 2^(attempt-1)
                backoff_base = self._get_retry_backoff_base()
                delay_seconds = backoff_base * (2 ** (attempt_count - 1))
                next_retry = datetime.utcnow() + timedelta(seconds=delay_seconds)
                next_retry_str = next_retry.strftime("%Y-%m-%d %H:%M:%S")

                conn.execute(
                    """UPDATE operation_queue
                       SET status = 'failed', attempt_count = ?,
                           error_message = ?, next_retry_at = ?
                       WHERE id = ?""",
                    (attempt_count, error, next_retry_str, operation_id),
                )
                logger.info(
                    "Operation %d failed (attempt %d/%d), retry at %s: %s",
                    operation_id, attempt_count, max_attempts,
                    next_retry_str, error,
                )

    def _get_retry_backoff_base(self) -> int:
        """Read retry_backoff_base from app_settings, default 30 seconds."""
        try:
            with get_db(self.db_path) as conn:
                row = conn.execute(
                    "SELECT retry_backoff_base FROM app_settings LIMIT 1"
                ).fetchone()
                if row and row["retry_backoff_base"] is not None:
                    return int(row["retry_backoff_base"])
        except Exception:
            logger.debug("Could not read retry_backoff_base from app_settings, using default")
        return 30

    def _maybe_delete_device_after_cleanup(self, device_id: int, device: dict) -> None:
        """After a successful decommission removal, check if the device should be deleted.

        Looks for any remaining pending/in_progress operations for this device.
        If none remain, deletes the device record and associated data.
        For floating_rule pfSense devices, also removes the floating rules and alias.
        """
        try:
            with get_db(self.db_path) as conn:
                remaining = conn.execute(
                    """SELECT COUNT(*) as cnt FROM operation_queue
                       WHERE device_id = ? AND status IN ('pending', 'in_progress')""",
                    (device_id,),
                ).fetchone()
                if remaining and remaining["cnt"] > 0:
                    return  # Still has pending work

            # For floating_rule pfSense devices, remove the floating rules and alias
            device_type = device.get("device_type")
            block_method = device.get("block_method")
            if device_type == "pfsense" and block_method == "floating_rule":
                try:
                    from clients.pfsense_client import PfSenseClient
                    client = PfSenseClient(
                        host=device["hostname"],
                        username=device.get("web_username", ""),
                        password=device.get("web_password", ""),
                        verify_ssl=False,
                        block_method=block_method,
                    )
                    client.remove_floating_rules(PFSENSE_ALIAS_NAME)
                    client.remove_alias(PFSENSE_ALIAS_NAME)
                    logger.info("Removed floating rules and alias for device %d", device_id)
                except Exception as exc:
                    logger.warning(
                        "Failed to remove floating rules/alias for device %d: %s",
                        device_id, exc,
                    )

            # Delete the device record and associated data
            with get_db(self.db_path) as conn:
                conn.execute("DELETE FROM operation_queue WHERE device_id = ?", (device_id,))
                conn.execute("DELETE FROM push_statuses WHERE device_id = ?", (device_id,))
                conn.execute("DELETE FROM managed_devices WHERE id = ?", (device_id,))

            logger.info("Device %d deleted after successful decommission cleanup", device_id)

            _write_audit_log(
                self.db_path,
                event_type="device_remove",
                action="device deleted after cleanup",
                device_id=device_id,
            )

        except Exception:
            logger.exception("Error in post-cleanup device deletion for device %d", device_id)

