"""Rules engine service for deterministic operation computation.

Central coordinator that computes the desired state of block rules for each
device, determines what operations are needed, and orchestrates their execution.
"""

import json
import logging
import threading
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from database import get_db
from services.blocklist_service import BlocklistService
from services.device_manager import DeviceManager

logger = logging.getLogger(__name__)

# Maximum IPs per operation for capacity-limited device types.
# Matches DEVICE_BATCH_SIZE in push_orchestrator.py — operations are
# split at creation time so each queue entry is a manageable chunk
# that the device can actually apply in one go.
OPERATION_BATCH_SIZE = {
    "aws_waf": 500,
    "azure_nsg": 200,
    "gcp_firewall": 200,
    "oci_nsg": 50,
}


def _write_audit_log(db_path, event_type, action, user=None, target_ips=None,
                     device_id=None, operation_id=None, details=None):
    """Write an entry to the audit_log table.

    Args:
        db_path: Path to the SQLite database file.
        event_type: Type of event (e.g. 'block', 'unblock', 'push', 'reconciliation',
                    'device_add', 'device_remove').
        action: Human-readable description of the action.
        user: Requesting user (None for system events).
        target_ips: List of affected IP addresses (will be JSON-serialized).
        device_id: ID of the managed device involved (optional).
        operation_id: UUID string of the related operation (optional).
        details: Dict of extra context (will be JSON-serialized).
    """
    target_ips_json = json.dumps(target_ips) if target_ips is not None else None
    details_json = json.dumps(details) if details is not None else None

    try:
        with get_db(db_path) as conn:
            conn.execute(
                """INSERT INTO audit_log
                   (event_type, user, action, target_ips, device_id, operation_id, details)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (event_type, user, action, target_ips_json, device_id,
                 operation_id, details_json),
            )
    except Exception:
        logger.exception("Failed to write audit log entry: event_type=%s action=%s",
                         event_type, action)


def cleanup_audit_log(db_path):
    """Delete audit_log entries older than the configured retention period.

    Reads ``audit_retention_days`` from ``app_settings`` (default 90) and
    removes all audit_log rows whose ``timestamp`` is older than
    ``utcnow() - retention_days``.

    Args:
        db_path: Path to the SQLite database file.

    Returns:
        int: Number of deleted audit_log entries.
    """
    with get_db(db_path) as conn:
        row = conn.execute(
            "SELECT audit_retention_days FROM app_settings LIMIT 1"
        ).fetchone()
        retention_days = row["audit_retention_days"] if row else 90

    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

    with get_db(db_path) as conn:
        cursor = conn.execute(
            "DELETE FROM audit_log WHERE timestamp < ?", (cutoff_str,)
        )
        deleted = cursor.rowcount

    logger.info("Audit log cleanup: deleted %d entries older than %s (retention=%d days)",
                deleted, cutoff_str, retention_days)
    return deleted


class RulesEngine:
    """Compute and orchestrate block-rule operations across managed devices."""

    def __init__(self, db_path=None):
        self.db_path = db_path
        self.blocklist_service = BlocklistService(db_path)
        self.device_manager = DeviceManager(db_path)
        self._compute_lock = threading.Lock()

    def compute_device_operations(self, device_id: int) -> List[Dict]:
        """Compare desired state vs push_statuses for a device.

        Computes the difference between the central blocklist (desired state)
        and the successfully pushed entries for the given device, then returns
        a list of operations needed to bring the device into sync.

        Uses a threading lock to serialize state computation and prevent race
        conditions when multiple callers request operations concurrently.

        Args:
            device_id: ID of the managed device to compute operations for.

        Returns:
            List of dicts with 'action' and 'ip_addresses' keys, e.g.
            [{"action": "add", "ip_addresses": ["1.2.3.4"]},
             {"action": "remove", "ip_addresses": ["5.6.7.8"]}].
            Only non-empty operations are included. Returns an empty list
            when the device is fully in sync.
        """
        with self._compute_lock:
            with get_db(self.db_path) as conn:
                # Desired state: all IPs in the central blocklist
                desired_rows = conn.execute(
                    "SELECT id, ip_address FROM block_entries"
                ).fetchall()
                desired_map = {row["ip_address"]: row["id"] for row in desired_rows}
                desired_ips = set(desired_map.keys())

                # Actual state: IPs successfully pushed to this device
                success_rows = conn.execute(
                    """SELECT be.ip_address
                       FROM push_statuses ps
                       JOIN block_entries be ON ps.block_entry_id = be.id
                       WHERE ps.device_id = ? AND ps.status = 'success'""",
                    (device_id,),
                ).fetchall()
                pushed_ips = {row["ip_address"] for row in success_rows}

            # Compute differences
            to_add = sorted(desired_ips - pushed_ips)
            to_remove = sorted(pushed_ips - desired_ips)

            operations = []
            if to_add:
                operations.append({"action": "add", "ip_addresses": to_add})
            if to_remove:
                operations.append({"action": "remove", "ip_addresses": to_remove})

            return operations

    def process_block(self, ip_addresses: List[str], user: str, note: str = "",
                      skip_invalid: bool = False) -> Dict:
        """Validate IPs, add to blocklist, enqueue operations for all devices.

        Validates all IPs via BlocklistService.add_ips_bulk(), then computes
        per-device operations and inserts them into the operation_queue with a
        shared UUID operation_id. Returns immediately without device communication.

        Args:
            ip_addresses: List of IPv4/IPv6 addresses or CIDR notations to block.
            user: Username of the person requesting the block.
            note: Optional note for the blocklist entries.
            skip_invalid: If True, skip bad/protected/duplicate IPs instead of
                rejecting the entire batch. Used by feed syncs.

        Returns:
            Dict with "operation_id" (str), "ips_added" (list of IP strings),
            and "errors" (list of error strings).
        """
        operation_id = str(uuid.uuid4())

        # Validate and add IPs to the blocklist
        result = self.blocklist_service.add_ips_bulk(
            ip_addresses, user, note, skip_invalid=skip_invalid
        )

        if result["errors"] and not skip_invalid:
            return {
                "operation_id": operation_id,
                "ips_added": [],
                "errors": result["errors"],
            }

        added_ips = [entry["ip_address"] for entry in result["added"]]
        added_entries = result["added"]

        if not added_ips:
            return {
                "operation_id": operation_id,
                "ips_added": [],
                "errors": result.get("errors", []),
            }

        # Get all managed devices
        devices = self.device_manager.get_all_devices()

        # Enqueue operations and create push_status records
        with get_db(self.db_path) as conn:
            for device in devices:
                device_type = device.get("device_type", "")
                batch_size = OPERATION_BATCH_SIZE.get(device_type, 0)

                # Split into batched operations for capacity-limited devices
                if batch_size and len(added_ips) > batch_size:
                    for i in range(0, len(added_ips), batch_size):
                        chunk = added_ips[i:i + batch_size]
                        conn.execute(
                            """INSERT INTO operation_queue
                               (operation_id, device_id, action, ip_addresses, status, source)
                               VALUES (?, ?, 'add', ?, 'pending', 'api')""",
                            (operation_id, device["id"], json.dumps(chunk)),
                        )
                else:
                    conn.execute(
                        """INSERT INTO operation_queue
                           (operation_id, device_id, action, ip_addresses, status, source)
                           VALUES (?, ?, 'add', ?, 'pending', 'api')""",
                        (operation_id, device["id"], json.dumps(added_ips)),
                    )

                # Create pending push_status records for each IP/device pair
                for entry in added_entries:
                    conn.execute(
                        """INSERT OR IGNORE INTO push_statuses
                           (block_entry_id, device_id, status)
                           VALUES (?, ?, 'pending')""",
                        (entry["id"], device["id"]),
                    )

        _write_audit_log(
            self.db_path,
            event_type="block",
            action="block requested",
            user=user,
            target_ips=added_ips,
            operation_id=operation_id,
        )

        return {
            "operation_id": operation_id,
            "ips_added": added_ips,
            "errors": result.get("errors", []),
        }

    def process_unblock(self, ip_addresses: List[str], user: str) -> Dict:
        """Remove IPs from blocklist, enqueue removal operations for all devices.

        Looks up block_entry IDs before removal (for push_status cleanup),
        removes IPs via BlocklistService.remove_ips_bulk(), then enqueues
        per-device removal operations. Returns immediately without device
        communication.

        Args:
            ip_addresses: List of IPv4/IPv6 addresses or CIDR notations to unblock.
            user: Username of the person requesting the unblock.

        Returns:
            Dict with "operation_id" (str), "ips_removed" (list of IP strings),
            and "errors" (list of error strings).
        """
        operation_id = str(uuid.uuid4())

        # Remove IPs from the blocklist atomically
        result = self.blocklist_service.remove_ips_bulk(ip_addresses)

        if result["errors"]:
            return {
                "operation_id": operation_id,
                "ips_removed": [],
                "errors": result["errors"],
            }

        removed_ips = result["removed"]

        if not removed_ips:
            return {
                "operation_id": operation_id,
                "ips_removed": [],
                "errors": [],
            }

        # Get all managed devices
        devices = self.device_manager.get_all_devices()

        # Enqueue removal operations for each device
        with get_db(self.db_path) as conn:
            for device in devices:
                device_type = device.get("device_type", "")
                batch_size = OPERATION_BATCH_SIZE.get(device_type, 0)

                if batch_size and len(removed_ips) > batch_size:
                    for i in range(0, len(removed_ips), batch_size):
                        chunk = removed_ips[i:i + batch_size]
                        conn.execute(
                            """INSERT INTO operation_queue
                               (operation_id, device_id, action, ip_addresses, status, source)
                               VALUES (?, ?, 'remove', ?, 'pending', 'api')""",
                            (operation_id, device["id"], json.dumps(chunk)),
                        )
                else:
                    conn.execute(
                        """INSERT INTO operation_queue
                           (operation_id, device_id, action, ip_addresses, status, source)
                           VALUES (?, ?, 'remove', ?, 'pending', 'api')""",
                        (operation_id, device["id"], json.dumps(removed_ips)),
                    )

        _write_audit_log(
            self.db_path,
            event_type="unblock",
            action="unblock requested",
            user=user,
            target_ips=removed_ips,
            operation_id=operation_id,
        )

        return {
            "operation_id": operation_id,
            "ips_removed": removed_ips,
            "errors": [],
        }

    def onboard_device(self, device_id: int) -> str:
        """Enqueue full blocklist push for a newly added device.

        Retrieves all current block_entries and enqueues operations to apply
        the complete blocklist to the specified device.  For capacity-limited
        device types (e.g. oci_nsg with a 50-rule limit), the IP list is
        split into batched operations so each queue entry is small enough
        for the device to apply in one call.

        Args:
            device_id: ID of the newly added managed device.

        Returns:
            A UUID operation_id string identifying the onboarding operation.
        """
        operation_id = str(uuid.uuid4())

        with get_db(self.db_path) as conn:
            # Look up device type for batch sizing
            device_row = conn.execute(
                "SELECT device_type FROM managed_devices WHERE id = ?",
                (device_id,),
            ).fetchone()
            device_type = device_row["device_type"] if device_row else None
            batch_size = OPERATION_BATCH_SIZE.get(device_type, 0)

            # Get all current block entries
            rows = conn.execute(
                "SELECT id, ip_address FROM block_entries"
            ).fetchall()

            if not rows:
                return operation_id

            all_ips = [row["ip_address"] for row in rows]

            # Skip IPs that already have a pending/in_progress operation
            # queued for this device (avoids duplicates when onboarding
            # races with a concurrent block operation).
            already_queued = set()
            pending_ops = conn.execute(
                """SELECT ip_addresses FROM operation_queue
                   WHERE device_id = ? AND action = 'add'
                     AND status IN ('pending', 'in_progress')""",
                (device_id,),
            ).fetchall()
            for pending_op in pending_ops:
                already_queued.update(json.loads(pending_op["ip_addresses"]))

            ips_to_push = [ip for ip in all_ips if ip not in already_queued]

            if not ips_to_push:
                return operation_id

            # Split into batched operations for capacity-limited devices
            if batch_size and len(ips_to_push) > batch_size:
                for i in range(0, len(ips_to_push), batch_size):
                    chunk = ips_to_push[i:i + batch_size]
                    conn.execute(
                        """INSERT INTO operation_queue
                           (operation_id, device_id, action, ip_addresses, status, source)
                           VALUES (?, ?, 'add', ?, 'pending', 'onboarding')""",
                        (operation_id, device_id, json.dumps(chunk)),
                    )
            else:
                conn.execute(
                    """INSERT INTO operation_queue
                       (operation_id, device_id, action, ip_addresses, status, source)
                       VALUES (?, ?, 'add', ?, 'pending', 'onboarding')""",
                    (operation_id, device_id, json.dumps(ips_to_push)),
                )

            # Create pending push_status records for each IP/device pair
            entry_map = {row["ip_address"]: row["id"] for row in rows}
            for ip in ips_to_push:
                entry_id = entry_map.get(ip)
                if entry_id:
                    conn.execute(
                        """INSERT OR IGNORE INTO push_statuses
                           (block_entry_id, device_id, status)
                           VALUES (?, ?, 'pending')""",
                        (entry_id, device_id),
                    )

        _write_audit_log(
            self.db_path,
            event_type="device_add",
            action="device onboarded",
            device_id=device_id,
            operation_id=operation_id,
        )

        return operation_id

    def decommission_device(self, device_id: int, cleanup: bool = True) -> str:
        """Decommission a managed device, optionally cleaning up block rules first.

        If cleanup=True, enqueues a 'remove' operation for all currently blocked
        IPs on the device and retains the device record until cleanup completes.
        If cleanup=False, immediately deletes the device record and all
        associated push_status records via DeviceManager.

        Args:
            device_id: ID of the managed device to decommission.
            cleanup: If True, enqueue rule removal before deleting the device.
                     If False, delete the device and push_statuses immediately.

        Returns:
            A UUID operation_id string identifying the decommission operation.
        """
        operation_id = str(uuid.uuid4())

        if cleanup:
            with get_db(self.db_path) as conn:
                # Get all current block entries to build the removal list
                rows = conn.execute(
                    "SELECT ip_address FROM block_entries"
                ).fetchall()

                all_ips = [row["ip_address"] for row in rows]

                if all_ips:
                    # Enqueue a 'remove' operation for this device
                    conn.execute(
                        """INSERT INTO operation_queue
                           (operation_id, device_id, action, ip_addresses, status, source)
                           VALUES (?, ?, 'remove', ?, 'pending', 'decommission')""",
                        (operation_id, device_id, json.dumps(all_ips)),
                    )
                else:
                    # No IPs to remove — delete device immediately
                    conn.execute("DELETE FROM operation_queue WHERE device_id = ?", (device_id,))
                    conn.execute("DELETE FROM push_statuses WHERE device_id = ?", (device_id,))
                    conn.execute("DELETE FROM managed_devices WHERE id = ?", (device_id,))
        else:
            # Immediate deletion — delegate to DeviceManager
            self.device_manager.remove_device(device_id, cleanup=False)

        _write_audit_log(
            self.db_path,
            event_type="device_remove",
            action="device decommissioned" if cleanup else "device removed immediately",
            device_id=device_id,
            operation_id=operation_id,
            details={"cleanup": cleanup},
        )

        return operation_id

    def get_operation_status(self, operation_id: str) -> Optional[Dict]:
        """Return current status of an operation and its per-device results.

        Queries the operation_queue for all records matching the given
        operation_id, then enriches each with per-device push_status
        information. Derives an overall status from the individual
        operation statuses.

        Args:
            operation_id: UUID string identifying the operation group.

        Returns:
            Dict with "operation_id", "status" (overall), and "devices"
            (list of per-device result dicts), or None if no records found.
        """
        with get_db(self.db_path) as conn:
            op_rows = conn.execute(
                """SELECT id, device_id, action, ip_addresses, status,
                          attempt_count, max_attempts, error_message,
                          created_at, started_at, completed_at, source
                   FROM operation_queue
                   WHERE operation_id = ?""",
                (operation_id,),
            ).fetchall()

            if not op_rows:
                return None

            devices = []
            for op in op_rows:
                ip_list = json.loads(op["ip_addresses"])

                # Query push_statuses for this device and the IPs in this operation
                push_rows = conn.execute(
                    """SELECT ps.status, ps.error_message
                       FROM push_statuses ps
                       JOIN block_entries be ON ps.block_entry_id = be.id
                       WHERE ps.device_id = ?
                         AND be.ip_address IN ({})""".format(
                        ",".join("?" for _ in ip_list)
                    ),
                    (op["device_id"], *ip_list),
                ).fetchall()

                devices.append({
                    "device_id": op["device_id"],
                    "action": op["action"],
                    "status": op["status"],
                    "ip_addresses": ip_list,
                    "error_message": op["error_message"],
                    "push_statuses": [
                        {
                            "status": pr["status"],
                            "error_message": pr["error_message"],
                        }
                        for pr in push_rows
                    ],
                })

            # Derive overall status from individual operation statuses
            statuses = {op["status"] for op in op_rows}
            if statuses == {"completed"}:
                overall = "completed"
            elif "in_progress" in statuses:
                overall = "in_progress"
            elif "failed" in statuses and "pending" not in statuses and "in_progress" not in statuses:
                overall = "failed"
            elif "pending" in statuses:
                overall = "pending"
            else:
                overall = "in_progress"

            return {
                "operation_id": operation_id,
                "status": overall,
                "devices": devices,
            }




