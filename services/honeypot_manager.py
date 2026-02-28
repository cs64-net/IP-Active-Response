"""HoneypotManager service for OpenCanary honeypot integration.

Manages honeypot instance registration, token authentication, and instance
lifecycle. Coordinates with BlocklistService and RulesEngine for IP blocking,
and writes audit log entries for all management operations.
"""

import hashlib
import json
import logging
import math
import os
import secrets
from datetime import datetime, timezone
from typing import Optional

from database import get_db
from services.blocklist_service import BlocklistService
from services.rules_engine import RulesEngine, _write_audit_log

logger = logging.getLogger(__name__)


class HoneypotManager:
    """Central service for honeypot instance management and alert processing."""

    def __init__(self, db_path=None, alert_forwarder=None):
        """Initialize with database path.

        Args:
            db_path: Path to the SQLite database file. Defaults to Config.DATABASE_PATH.
            alert_forwarder: Optional AlertForwarder instance for SIEM forwarding.
        """
        self.db_path = db_path
        self.blocklist_service = BlocklistService(db_path=db_path)
        self.rules_engine = RulesEngine(db_path=db_path)
        self.alert_forwarder = alert_forwarder

    def register_instance(self, name: str, ip_address: str, services: list) -> dict:
        """Register a new honeypot instance.

        Generates a unique API token, stores the SHA-256 hash, and creates
        the instance record. The raw token is returned once and never stored.

        Args:
            name: Unique instance name.
            ip_address: Unique IP address of the honeypot.
            services: List of emulated service names.

        Returns:
            Dict with instance details and the raw API token (shown once).

        Raises:
            ValueError: If name or IP address is already registered.
        """
        raw_token = "hpt_" + secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        token_prefix = raw_token[:8]

        services_json = json.dumps(services) if isinstance(services, list) else services

        with get_db(self.db_path) as conn:
            # Check for duplicate name
            existing = conn.execute(
                "SELECT id FROM honeypot_instances WHERE name = ?", (name,)
            ).fetchone()
            if existing:
                raise ValueError(f"Instance name '{name}' is already registered.")

            # Check for duplicate IP
            existing = conn.execute(
                "SELECT id FROM honeypot_instances WHERE ip_address = ?", (ip_address,)
            ).fetchone()
            if existing:
                raise ValueError(f"IP address '{ip_address}' is already registered.")

            cursor = conn.execute(
                """INSERT INTO honeypot_instances
                   (name, ip_address, services, token_hash, token_prefix)
                   VALUES (?, ?, ?, ?, ?)""",
                (name, ip_address, services_json, token_hash, token_prefix),
            )
            instance_id = cursor.lastrowid

        _write_audit_log(
            self.db_path,
            event_type="honeypot_management",
            action=f"Registered honeypot instance '{name}' ({ip_address})",
            details={
                "instance_id": instance_id,
                "name": name,
                "ip_address": ip_address,
                "services": services if isinstance(services, list) else json.loads(services),
            },
        )

        logger.info("Registered honeypot instance '%s' (id=%d, ip=%s)", name, instance_id, ip_address)

        return {
            "id": instance_id,
            "name": name,
            "ip_address": ip_address,
            "services": services if isinstance(services, list) else json.loads(services),
            "token": raw_token,
            "token_prefix": token_prefix + "...",
        }

    def delete_instance(self, instance_id: int) -> None:
        """Delete a honeypot instance, revoke its token, and unblock associated IPs.

        Collects IPs that were only blocked because of this instance (no other
        honeypot instances or non-honeypot sources) and unblocks them via
        RulesEngine. The ON DELETE CASCADE constraint removes associated alerts
        and honeypot_block_entries automatically.

        Args:
            instance_id: ID of the instance to delete.

        Raises:
            ValueError: If the instance does not exist.
        """
        ips_to_unblock = []

        with get_db(self.db_path) as conn:
            row = conn.execute(
                "SELECT name, ip_address FROM honeypot_instances WHERE id = ?",
                (instance_id,),
            ).fetchone()
            if not row:
                raise ValueError(f"Honeypot instance with id {instance_id} not found.")

            name = row["name"]
            ip_address = row["ip_address"]

            # Collect IPs blocked by this instance
            blocked_rows = conn.execute(
                "SELECT DISTINCT ip_address FROM honeypot_block_entries WHERE instance_id = ?",
                (instance_id,),
            ).fetchall()

            for brow in blocked_rows:
                ip = brow["ip_address"]

                # Check if this IP is also blocked by OTHER honeypot instances
                other_honeypot = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM honeypot_block_entries"
                    " WHERE ip_address = ? AND instance_id != ?",
                    (ip, instance_id),
                ).fetchone()
                if other_honeypot and other_honeypot["cnt"] > 0:
                    continue

                # Check if this IP has non-honeypot sources in block_entries
                non_honeypot = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM block_entries"
                    " WHERE ip_address = ? AND added_by NOT LIKE 'honeypot:%'",
                    (ip,),
                ).fetchone()
                if non_honeypot and non_honeypot["cnt"] > 0:
                    continue

                ips_to_unblock.append(ip)

            conn.execute(
                "DELETE FROM honeypot_instances WHERE id = ?", (instance_id,)
            )

        # Unblock IPs that were only associated with this instance
        if ips_to_unblock:
            try:
                self.rules_engine.process_unblock(ips_to_unblock, f"honeypot:instance_deleted:{name}")
            except Exception:
                logger.exception(
                    "Failed to unblock %d IPs after deleting instance '%s'",
                    len(ips_to_unblock), name,
                )

        _write_audit_log(
            self.db_path,
            event_type="honeypot_management",
            action=f"Deleted honeypot instance '{name}' ({ip_address})",
            details={
                "instance_id": instance_id,
                "name": name,
                "ip_address": ip_address,
                "unblocked_ips": ips_to_unblock,
            },
        )

        logger.info(
            "Deleted honeypot instance '%s' (id=%d), unblocked %d IPs",
            name, instance_id, len(ips_to_unblock),
        )

    def get_instance(self, instance_id: int) -> dict:
        """Get a single honeypot instance by ID.

        Args:
            instance_id: ID of the instance.

        Returns:
            Dict with instance details and computed status.

        Raises:
            ValueError: If the instance does not exist.
        """
        with get_db(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM honeypot_instances WHERE id = ?", (instance_id,)
            ).fetchone()
            if not row:
                raise ValueError(f"Honeypot instance with id {instance_id} not found.")

            settings = self._get_staleness_threshold(conn)
            return self._row_to_instance_dict(row, settings)

    def get_all_instances(self) -> list:
        """Return all registered honeypot instances with computed status.

        Status is computed based on last_alert_at and the staleness threshold:
        - pending: last_alert_at is NULL (no alerts received yet)
        - active: last_alert_at is within the staleness threshold
        - stale: last_alert_at is older than the staleness threshold

        Returns:
            List of instance dicts with computed status field.
        """
        with get_db(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM honeypot_instances ORDER BY registered_at DESC"
            ).fetchall()

            staleness_threshold = self._get_staleness_threshold(conn)
            return [self._row_to_instance_dict(row, staleness_threshold) for row in rows]

    def get_instance_by_token(self, raw_token: str) -> Optional[dict]:
        """Look up a honeypot instance by its raw API token.

        Hashes the provided token and compares against stored hashes.

        Args:
            raw_token: The raw API token string.

        Returns:
            Instance dict if found, None otherwise.
        """
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        with get_db(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM honeypot_instances WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if not row:
                return None

            staleness_threshold = self._get_staleness_threshold(conn)
            return self._row_to_instance_dict(row, staleness_threshold)

    def touch_instance(self, instance_id: int) -> None:
        """Update last_alert_at to mark the instance as active (heartbeat)."""
        with get_db(self.db_path) as conn:
            conn.execute(
                "UPDATE honeypot_instances SET last_alert_at = CURRENT_TIMESTAMP WHERE id = ?",
                (instance_id,),
            )

    def unblock_ip(self, ip_address: str) -> None:
        """Remove a honeypot-blocked IP from block_entries and honeypot_block_entries.

        If the IP also has non-honeypot sources, only the honeypot_block_entries
        rows are removed (the block_entries row is preserved).

        Args:
            ip_address: The IP address to unblock.

        Raises:
            ValueError: If the IP is not in honeypot_block_entries.
        """
        with get_db(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM honeypot_block_entries WHERE ip_address = ?",
                (ip_address,),
            ).fetchone()
            if not existing:
                raise ValueError(f"IP {ip_address} is not in the honeypot block list.")

            # Remove honeypot_block_entries
            conn.execute(
                "DELETE FROM honeypot_block_entries WHERE ip_address = ?",
                (ip_address,),
            )

            # Check if IP has non-honeypot sources
            non_honeypot = conn.execute(
                "SELECT COUNT(*) AS cnt FROM block_entries"
                " WHERE ip_address = ? AND added_by NOT LIKE 'honeypot:%'",
                (ip_address,),
            ).fetchone()
            has_other_sources = non_honeypot["cnt"] > 0 if non_honeypot else False

        # If only honeypot source, unblock from devices too
        if not has_other_sources:
            try:
                self.rules_engine.process_unblock([ip_address], "honeypot:manual_unblock")
            except Exception:
                logger.exception("Failed to unblock %s via RulesEngine", ip_address)

        _write_audit_log(
            self.db_path,
            event_type="honeypot_management",
            action=f"Manually unblocked honeypot IP {ip_address}",
            target_ips=[ip_address],
            details={"ip_address": ip_address, "has_other_sources": has_other_sources},
        )
        logger.info("Manually unblocked honeypot IP %s", ip_address)

    # ── Internal Helpers ──

    def _get_staleness_threshold(self, conn) -> int:
        """Read the honeypot_staleness_threshold from app_settings.

        Args:
            conn: Active database connection.

        Returns:
            Staleness threshold in seconds (default 3600).
        """
        row = conn.execute(
            "SELECT honeypot_staleness_threshold FROM app_settings WHERE id = 1"
        ).fetchone()
        if row and row["honeypot_staleness_threshold"] is not None:
            return row["honeypot_staleness_threshold"]
        return 3600

    # ── Alert Processing ──

    def process_alert(self, instance_id: int, attacker_ip: str, service_name: str,
                      timestamp: str, raw_payload: str = None) -> dict:
        """Process a validated honeypot alert.

        Validates the attacker IP against protected ranges, stores the alert
        record, and either blocks the IP (new) or updates existing block info.
        Updates threat indicators after each alert.

        Args:
            instance_id: ID of the honeypot instance that generated the alert.
            attacker_ip: The attacker's IP address.
            service_name: Name of the triggered service (e.g. 'ssh', 'ftp').
            timestamp: Alert timestamp string from the honeypot.

        Returns:
            Dict with 'action' key: 'blocked', 'updated', or 'skipped_protected'.
        """
        import ipaddress as _ipaddress

        # Normalize the IP for consistent storage/lookup
        ip_str = attacker_ip.strip()
        if "/" in ip_str:
            network = _ipaddress.ip_network(ip_str, strict=False)
            normalized_ip = str(network)
        else:
            addr = _ipaddress.ip_address(ip_str)
            suffix = "/128" if isinstance(addr, _ipaddress.IPv6Address) else "/32"
            normalized_ip = str(addr) + suffix

        # Look up instance name outside the main transaction
        with get_db(self.db_path) as conn:
            instance_row = conn.execute(
                "SELECT name FROM honeypot_instances WHERE id = ?",
                (instance_id,),
            ).fetchone()
            instance_name = instance_row["name"] if instance_row else f"instance-{instance_id}"

        # Check protected ranges before opening the main transaction
        is_protected = False
        try:
            self.blocklist_service._check_protected_ranges(normalized_ip)
        except ValueError:
            is_protected = True

        if is_protected:
            with get_db(self.db_path) as conn:
                # Store alert with skipped_protected status
                conn.execute(
                    """INSERT INTO honeypot_alerts
                       (attacker_ip, service_name, instance_id, alert_timestamp, status, raw_payload)
                       VALUES (?, ?, ?, ?, 'skipped_protected', ?)""",
                    (normalized_ip, service_name, instance_id, timestamp, raw_payload),
                )
                # Update instance last_alert_at and alert_count
                conn.execute(
                    """UPDATE honeypot_instances
                       SET last_alert_at = CURRENT_TIMESTAMP, alert_count = alert_count + 1
                       WHERE id = ?""",
                    (instance_id,),
                )
            logger.warning(
                "Honeypot alert for protected IP %s from instance '%s' — skipped",
                normalized_ip, instance_name,
            )
            _write_audit_log(
                self.db_path,
                event_type="honeypot_alert",
                action=f"Skipped protected IP {normalized_ip} from honeypot '{instance_name}' ({service_name})",
                target_ips=[normalized_ip],
                details={
                    "instance_id": instance_id,
                    "instance_name": instance_name,
                    "service_name": service_name,
                    "status": "skipped_protected",
                },
            )
            if self.alert_forwarder is not None:
                self.alert_forwarder.forward_alert({
                    "attacker_ip": normalized_ip,
                    "service_name": service_name,
                    "instance_id": instance_id,
                    "instance_name": instance_name,
                    "alert_timestamp": timestamp,
                    "status": "skipped_protected",
                    "raw_payload": raw_payload,
                })
            return {"action": "skipped_protected"}

        with get_db(self.db_path) as conn:
            # Check if IP is already in block_entries
            existing_block = conn.execute(
                "SELECT id FROM block_entries WHERE ip_address = ?",
                (normalized_ip,),
            ).fetchone()

            added_by = f"honeypot:{instance_name}"
            note = f"Honeypot alert: {service_name} on {instance_name}"

            if existing_block is None:
                # New IP — block it
                conn.execute(
                    """INSERT INTO honeypot_alerts
                       (attacker_ip, service_name, instance_id, alert_timestamp, status, raw_payload)
                       VALUES (?, ?, ?, ?, 'blocked', ?)""",
                    (normalized_ip, service_name, instance_id, timestamp, raw_payload),
                )
                # Insert honeypot_block_entries
                conn.execute(
                    """INSERT OR IGNORE INTO honeypot_block_entries
                       (ip_address, instance_id, service_name)
                       VALUES (?, ?, ?)""",
                    (normalized_ip, instance_id, service_name),
                )
                # Update instance last_alert_at and alert_count
                conn.execute(
                    """UPDATE honeypot_instances
                       SET last_alert_at = CURRENT_TIMESTAMP, alert_count = alert_count + 1
                       WHERE id = ?""",
                    (instance_id,),
                )
                # Update threat indicators
                self._update_threat_indicators(conn, normalized_ip)

            else:
                # Already blocked — update
                conn.execute(
                    """INSERT INTO honeypot_alerts
                       (attacker_ip, service_name, instance_id, alert_timestamp, status, raw_payload)
                       VALUES (?, ?, ?, ?, 'updated', ?)""",
                    (normalized_ip, service_name, instance_id, timestamp, raw_payload),
                )
                # Upsert honeypot_block_entries for this instance/service combo
                conn.execute(
                    """INSERT OR IGNORE INTO honeypot_block_entries
                       (ip_address, instance_id, service_name)
                       VALUES (?, ?, ?)""",
                    (normalized_ip, instance_id, service_name),
                )
                # Update instance last_alert_at and alert_count
                conn.execute(
                    """UPDATE honeypot_instances
                       SET last_alert_at = CURRENT_TIMESTAMP, alert_count = alert_count + 1
                       WHERE id = ?""",
                    (instance_id,),
                )
                # Update threat indicators
                self._update_threat_indicators(conn, normalized_ip)

        # Perform blocking outside the main transaction for new IPs
        if existing_block is None:
            try:
                self.rules_engine.process_block(
                    [attacker_ip], added_by, note
                )
            except Exception:
                logger.exception(
                    "Failed to push block for %s via RulesEngine", normalized_ip
                )

            _write_audit_log(
                self.db_path,
                event_type="honeypot_block",
                action=f"Blocked {normalized_ip} via honeypot '{instance_name}' ({service_name})",
                user=added_by,
                target_ips=[normalized_ip],
                details={
                    "instance_id": instance_id,
                    "instance_name": instance_name,
                    "service_name": service_name,
                },
            )
            logger.info(
                "Blocked IP %s from honeypot '%s' (service: %s)",
                normalized_ip, instance_name, service_name,
            )
            if self.alert_forwarder is not None:
                self.alert_forwarder.forward_alert({
                    "attacker_ip": normalized_ip,
                    "service_name": service_name,
                    "instance_id": instance_id,
                    "instance_name": instance_name,
                    "alert_timestamp": timestamp,
                    "status": "blocked",
                    "raw_payload": raw_payload,
                })
            return {"action": "blocked"}
        else:
            _write_audit_log(
                self.db_path,
                event_type="honeypot_alert",
                action=f"Repeat detection of {normalized_ip} from honeypot '{instance_name}' ({service_name})",
                user=added_by,
                target_ips=[normalized_ip],
                details={
                    "instance_id": instance_id,
                    "instance_name": instance_name,
                    "service_name": service_name,
                    "status": "updated",
                },
            )
            logger.info(
                "Updated existing block for IP %s from honeypot '%s' (service: %s)",
                normalized_ip, instance_name, service_name,
            )
            if self.alert_forwarder is not None:
                self.alert_forwarder.forward_alert({
                    "attacker_ip": normalized_ip,
                    "service_name": service_name,
                    "instance_id": instance_id,
                    "instance_name": instance_name,
                    "alert_timestamp": timestamp,
                    "status": "updated",
                    "raw_payload": raw_payload,
                })
            return {"action": "updated"}

    def _update_threat_indicators(self, conn, attacker_ip: str) -> None:
        """Recompute lateral_movement and port_scanner flags for an IP.

        Sets lateral_movement=1 if the IP has been seen on 2+ distinct instances.
        Sets port_scanner=1 if the IP has been seen on 3+ distinct services.

        Args:
            conn: Active database connection.
            attacker_ip: The normalized attacker IP address.
        """
        # Count distinct instances for this IP
        row = conn.execute(
            "SELECT COUNT(DISTINCT instance_id) AS cnt FROM honeypot_block_entries WHERE ip_address = ?",
            (attacker_ip,),
        ).fetchone()
        distinct_instances = row["cnt"] if row else 0

        # Count distinct services for this IP
        row = conn.execute(
            "SELECT COUNT(DISTINCT service_name) AS cnt FROM honeypot_block_entries WHERE ip_address = ?",
            (attacker_ip,),
        ).fetchone()
        distinct_services = row["cnt"] if row else 0

        lateral_movement = 1 if distinct_instances >= 2 else 0
        port_scanner = 1 if distinct_services >= 3 else 0

        # Update all rows for this IP
        conn.execute(
            """UPDATE honeypot_block_entries
               SET lateral_movement = ?, port_scanner = ?
               WHERE ip_address = ?""",
            (lateral_movement, port_scanner, attacker_ip),
        )

    # ── Expiry and Cleanup ──

    def run_expiry_check(self) -> dict:
        """Check for expired honeypot blocks and remove them.

        Reads honeypot_timeout from app_settings. If timeout is 0, blocks are
        permanent and no expiry is performed. For each expired IP:
        - If the IP has non-honeypot sources in block_entries, only remove
          the honeypot_block_entries association.
        - If the IP is only from honeypot sources, call RulesEngine.process_unblock
          to remove from block_entries and enqueue device removal operations.
        Writes audit_log entries with event_type 'honeypot_expiry' for each expired IP.

        Returns:
            Dict with 'expired_count' (int) and 'expired_ips' (list of str).
        """
        try:
            expired_ips = []
            ips_to_unblock = []
            audit_entries = []
            timeout = 86400

            with get_db(self.db_path) as conn:
                # Read timeout from app_settings
                settings_row = conn.execute(
                    "SELECT honeypot_timeout FROM app_settings WHERE id = 1"
                ).fetchone()
                timeout = settings_row["honeypot_timeout"] if settings_row and settings_row["honeypot_timeout"] is not None else 86400

                # timeout=0 means permanent — skip expiry entirely
                if timeout == 0:
                    return {"expired_count": 0, "expired_ips": []}

                # Find expired honeypot block entries
                # blocked_at + timeout seconds < now
                expired_rows = conn.execute(
                    "SELECT DISTINCT ip_address FROM honeypot_block_entries"
                    " WHERE CAST(strftime('%s', blocked_at) AS INTEGER) + ? < CAST(strftime('%s', 'now') AS INTEGER)",
                    (timeout,),
                ).fetchall()

                if not expired_rows:
                    return {"expired_count": 0, "expired_ips": []}

                expired_ips = [row["ip_address"] for row in expired_rows]

                for ip in expired_ips:
                    # Check if IP has non-honeypot sources in block_entries
                    non_honeypot = conn.execute(
                        "SELECT COUNT(*) AS cnt FROM block_entries"
                        " WHERE ip_address = ? AND added_by NOT LIKE 'honeypot:%'",
                        (ip,),
                    ).fetchone()

                    has_other_sources = non_honeypot["cnt"] > 0 if non_honeypot else False

                    # Remove honeypot_block_entries for this IP (all expired entries)
                    conn.execute(
                        "DELETE FROM honeypot_block_entries"
                        " WHERE ip_address = ? AND CAST(strftime('%s', blocked_at) AS INTEGER) + ? < CAST(strftime('%s', 'now') AS INTEGER)",
                        (ip, timeout),
                    )

                    if not has_other_sources:
                        # IP only from honeypot — queue for unblock
                        ips_to_unblock.append(ip)

                    # Collect audit log data for writing after transaction commits
                    audit_entries.append({
                        "ip": ip,
                        "timeout": timeout,
                        "has_other_sources": has_other_sources,
                    })

            # Write audit logs outside the main transaction to avoid locking
            for entry in audit_entries:
                _write_audit_log(
                    self.db_path,
                    event_type="honeypot_expiry",
                    action=f"Honeypot block expired for {entry['ip']} (timeout={entry['timeout']}s, retained={'yes' if entry['has_other_sources'] else 'no'})",
                    target_ips=[entry["ip"]],
                    details={
                        "ip_address": entry["ip"],
                        "timeout": entry["timeout"],
                        "has_other_sources": entry["has_other_sources"],
                    },
                )

            # Process unblocks outside the main transaction
            if ips_to_unblock:
                try:
                    self.rules_engine.process_unblock(ips_to_unblock, "honeypot:expiry")
                except Exception:
                    logger.exception("Failed to process unblock for expired honeypot IPs: %s", ips_to_unblock)

            logger.info("Honeypot expiry check: expired %d IPs, unblocked %d", len(expired_ips), len(ips_to_unblock))
            return {"expired_count": len(expired_ips), "expired_ips": expired_ips}

        except Exception:
            logger.exception("Error during honeypot expiry check")
            return {"expired_count": 0, "expired_ips": []}

    def cleanup_old_alerts(self) -> int:
        """Delete alerts beyond the 10,000 record cap.

        Retains only the most recent 10,000 alerts by received_at timestamp.
        Older records are deleted.

        Returns:
            Count of deleted alert records.
        """
        try:
            with get_db(self.db_path) as conn:
                # Count total alerts
                count_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM honeypot_alerts"
                ).fetchone()
                total = count_row["cnt"] if count_row else 0

                if total <= 10000:
                    return 0

                # Delete alerts beyond the 10,000 cap (keep most recent)
                cursor = conn.execute(
                    """DELETE FROM honeypot_alerts
                       WHERE id NOT IN (
                           SELECT id FROM honeypot_alerts
                           ORDER BY received_at DESC
                           LIMIT 10000
                       )"""
                )
                deleted = cursor.rowcount

            if deleted > 0:
                logger.info("Cleaned up %d old honeypot alerts (cap: 10,000)", deleted)

            return deleted

        except Exception:
            logger.exception("Error during honeypot alert cleanup")
            return 0





    # ── Configuration ──

    def get_settings(self) -> dict:
        """Return honeypot settings from app_settings.

        Returns:
            Dict with honeypot settings and SIEM forwarding configuration.
        """
        with get_db(self.db_path) as conn:
            row = conn.execute(
                "SELECT honeypot_timeout, honeypot_staleness_threshold,"
                " elastic_enabled, elastic_host, elastic_index, elastic_api_key, elastic_tls_verify,"
                " syslog_enabled, syslog_host, syslog_port, syslog_protocol, syslog_facility"
                " FROM app_settings WHERE id = 1"
            ).fetchone()
            if row:
                return {
                    "honeypot_timeout": row["honeypot_timeout"] if row["honeypot_timeout"] is not None else 86400,
                    "honeypot_staleness_threshold": row["honeypot_staleness_threshold"] if row["honeypot_staleness_threshold"] is not None else 3600,
                    "elastic_enabled": row["elastic_enabled"] if row["elastic_enabled"] is not None else 0,
                    "elastic_host": row["elastic_host"] or "",
                    "elastic_index": row["elastic_index"] if row["elastic_index"] is not None else "honeypot-alerts",
                    "elastic_api_key": row["elastic_api_key"] or "",
                    "elastic_tls_verify": row["elastic_tls_verify"] if row["elastic_tls_verify"] is not None else 1,
                    "syslog_enabled": row["syslog_enabled"] if row["syslog_enabled"] is not None else 0,
                    "syslog_host": row["syslog_host"] or "",
                    "syslog_port": row["syslog_port"] if row["syslog_port"] is not None else 514,
                    "syslog_protocol": row["syslog_protocol"] if row["syslog_protocol"] is not None else "udp",
                    "syslog_facility": row["syslog_facility"] if row["syslog_facility"] is not None else "local0",
                }
            return {
                "honeypot_timeout": 86400,
                "honeypot_staleness_threshold": 3600,
                "elastic_enabled": 0,
                "elastic_host": "",
                "elastic_index": "honeypot-alerts",
                "elastic_api_key": "",
                "elastic_tls_verify": 1,
                "syslog_enabled": 0,
                "syslog_host": "",
                "syslog_port": 514,
                "syslog_protocol": "udp",
                "syslog_facility": "local0",
            }

    def update_settings(self, timeout=None, staleness_threshold=None,
                         elastic_enabled=None, elastic_host=None,
                         elastic_index=None, elastic_api_key=None,
                         elastic_tls_verify=None, syslog_enabled=None,
                         syslog_host=None, syslog_port=None,
                         syslog_protocol=None, syslog_facility=None) -> dict:
        """Update honeypot settings in app_settings.

        Validates timeout: must be 0 or in range [300, 2592000].
        Validates staleness_threshold: must be > 0.
        Validates SIEM fields when enabled.

        Args:
            timeout: New honeypot_timeout value, or None to leave unchanged.
            staleness_threshold: New honeypot_staleness_threshold value, or None to leave unchanged.
            elastic_enabled: 1 to enable Elasticsearch forwarding, 0 to disable.
            elastic_host: Elasticsearch host URL (must be http:// or https:// when enabled).
            elastic_index: Elasticsearch index name. Defaults to 'honeypot-alerts'.
            elastic_api_key: API key for Elasticsearch authentication.
            elastic_tls_verify: 1 to verify TLS certs, 0 to skip.
            syslog_enabled: 1 to enable Syslog forwarding, 0 to disable.
            syslog_host: Syslog server hostname (must be non-empty when enabled).
            syslog_port: Syslog server port (must be 1-65535 when enabled). Defaults to 514.
            syslog_protocol: Transport protocol ('udp', 'tcp', 'tcp+tls').
            syslog_facility: Syslog facility name. Defaults to 'local0'.

        Returns:
            Dict with updated settings.

        Raises:
            ValueError: If any setting value is invalid.
        """
        if timeout is not None:
            if not isinstance(timeout, int):
                raise ValueError("Timeout must be an integer.")
            if timeout != 0 and (timeout < 300 or timeout > 2592000):
                raise ValueError(
                    "Timeout must be 0 (permanent) or between 300 and 2592000 seconds."
                )

        if staleness_threshold is not None:
            if not isinstance(staleness_threshold, int):
                raise ValueError("Staleness threshold must be an integer.")
            if staleness_threshold <= 0:
                raise ValueError("Staleness threshold must be greater than 0.")

        # Apply defaults for SIEM fields
        if elastic_index is not None and not elastic_index:
            elastic_index = "honeypot-alerts"
        if syslog_port is None and syslog_enabled:
            syslog_port = 514
        if syslog_facility is not None and not syslog_facility:
            syslog_facility = "local0"

        # Validate Elasticsearch settings when enabled
        if elastic_enabled:
            host = elastic_host or ""
            if not (host.startswith("http://") or host.startswith("https://")):
                raise ValueError(
                    "Elasticsearch host must be a valid HTTP or HTTPS URL."
                )

        # Validate Syslog settings when enabled
        if syslog_enabled:
            if not syslog_host:
                raise ValueError(
                    "Syslog host must be a non-empty string when Syslog is enabled."
                )
            if syslog_port is not None:
                if not isinstance(syslog_port, int):
                    raise ValueError("Syslog port must be an integer.")
                if syslog_port < 1 or syslog_port > 65535:
                    raise ValueError(
                        "Syslog port must be between 1 and 65535."
                    )

        with get_db(self.db_path) as conn:
            if timeout is not None:
                conn.execute(
                    "UPDATE app_settings SET honeypot_timeout = ? WHERE id = 1",
                    (timeout,),
                )
            if staleness_threshold is not None:
                conn.execute(
                    "UPDATE app_settings SET honeypot_staleness_threshold = ? WHERE id = 1",
                    (staleness_threshold,),
                )
            if elastic_enabled is not None:
                conn.execute(
                    "UPDATE app_settings SET elastic_enabled = ? WHERE id = 1",
                    (elastic_enabled,),
                )
            if elastic_host is not None:
                conn.execute(
                    "UPDATE app_settings SET elastic_host = ? WHERE id = 1",
                    (elastic_host,),
                )
            if elastic_index is not None:
                conn.execute(
                    "UPDATE app_settings SET elastic_index = ? WHERE id = 1",
                    (elastic_index,),
                )
            if elastic_api_key is not None:
                conn.execute(
                    "UPDATE app_settings SET elastic_api_key = ? WHERE id = 1",
                    (elastic_api_key,),
                )
            if elastic_tls_verify is not None:
                conn.execute(
                    "UPDATE app_settings SET elastic_tls_verify = ? WHERE id = 1",
                    (elastic_tls_verify,),
                )
            if syslog_enabled is not None:
                conn.execute(
                    "UPDATE app_settings SET syslog_enabled = ? WHERE id = 1",
                    (syslog_enabled,),
                )
            if syslog_host is not None:
                conn.execute(
                    "UPDATE app_settings SET syslog_host = ? WHERE id = 1",
                    (syslog_host,),
                )
            if syslog_port is not None:
                conn.execute(
                    "UPDATE app_settings SET syslog_port = ? WHERE id = 1",
                    (syslog_port,),
                )
            if syslog_protocol is not None:
                conn.execute(
                    "UPDATE app_settings SET syslog_protocol = ? WHERE id = 1",
                    (syslog_protocol,),
                )
            if syslog_facility is not None:
                conn.execute(
                    "UPDATE app_settings SET syslog_facility = ? WHERE id = 1",
                    (syslog_facility,),
                )

        logger.info(
            "Updated honeypot settings: timeout=%s, staleness_threshold=%s, "
            "elastic_enabled=%s, syslog_enabled=%s",
            timeout, staleness_threshold, elastic_enabled, syslog_enabled,
        )
        return self.get_settings()

    # ── Query / Stats ──

    def get_alerts(self, page: int = 1, per_page: int = 50, search: str = None) -> dict:
        """Return paginated, filterable alert history sorted by received_at DESC.

        Search filters by attacker_ip, service_name, or instance name (case-insensitive).

        Args:
            page: Page number (1-based).
            per_page: Number of alerts per page.
            search: Optional search term to filter results.

        Returns:
            Dict with 'alerts' (list), 'total' (int), 'page' (int), 'pages' (int).
        """
        with get_db(self.db_path) as conn:
            base_query = """
                FROM honeypot_alerts ha
                LEFT JOIN honeypot_instances hi ON ha.instance_id = hi.id
            """
            params = []

            if search:
                search_term = f"%{search}%"
                base_query += """
                    WHERE (ha.attacker_ip LIKE ? COLLATE NOCASE
                           OR ha.service_name LIKE ? COLLATE NOCASE
                           OR hi.name LIKE ? COLLATE NOCASE)
                """
                params = [search_term, search_term, search_term]

            # Get total count
            count_row = conn.execute(
                f"SELECT COUNT(*) AS cnt {base_query}", params
            ).fetchone()
            total = count_row["cnt"] if count_row else 0

            pages = max(1, math.ceil(total / per_page))
            offset = (page - 1) * per_page

            # Get paginated results
            rows = conn.execute(
                f"""SELECT ha.id, ha.attacker_ip, ha.service_name, ha.instance_id,
                           ha.alert_timestamp, ha.received_at, ha.status,
                           ha.raw_payload,
                           hi.name AS instance_name
                    {base_query}
                    ORDER BY ha.received_at DESC
                    LIMIT ? OFFSET ?""",
                params + [per_page, offset],
            ).fetchall()

            alerts = []
            for row in rows:
                alerts.append({
                    "id": row["id"],
                    "attacker_ip": row["attacker_ip"],
                    "service_name": row["service_name"],
                    "instance_id": row["instance_id"],
                    "instance_name": row["instance_name"],
                    "alert_timestamp": row["alert_timestamp"],
                    "received_at": row["received_at"],
                    "status": row["status"],
                    "raw_payload": row["raw_payload"],
                })

            return {
                "alerts": alerts,
                "total": total,
                "page": page,
                "pages": pages,
            }

    def get_blocked_ips(self) -> list:
        """Return all currently honeypot-blocked IPs with instance/service/threat info.

        Joins honeypot_block_entries with honeypot_instances to include instance name.

        Returns:
            List of dicts with ip_address, instance_id, instance_name, service_name,
            blocked_at, lateral_movement, port_scanner.
        """
        with get_db(self.db_path) as conn:
            rows = conn.execute(
                """SELECT hbe.ip_address, hbe.instance_id, hbe.service_name,
                          hbe.blocked_at, hbe.lateral_movement, hbe.port_scanner,
                          hi.name AS instance_name
                   FROM honeypot_block_entries hbe
                   LEFT JOIN honeypot_instances hi ON hbe.instance_id = hi.id
                   ORDER BY hbe.blocked_at DESC"""
            ).fetchall()

            return [
                {
                    "ip_address": row["ip_address"],
                    "instance_id": row["instance_id"],
                    "instance_name": row["instance_name"],
                    "service_name": row["service_name"],
                    "blocked_at": row["blocked_at"],
                    "lateral_movement": bool(row["lateral_movement"]),
                    "port_scanner": bool(row["port_scanner"]),
                }
                for row in rows
            ]

    def get_stats(self) -> dict:
        """Return summary statistics for the honeypot system.

        Returns:
            Dict with total_instances, active_instances, alerts_24h, blocked_ips,
            offline_bundle_available, and offline_bundle_size_bytes.
        """
        with get_db(self.db_path) as conn:
            # Total instances
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM honeypot_instances"
            ).fetchone()
            total_instances = row["cnt"] if row else 0

            # Active instances (using staleness threshold logic)
            staleness_threshold = self._get_staleness_threshold(conn)
            row = conn.execute(
                """SELECT COUNT(*) AS cnt FROM honeypot_instances
                   WHERE last_alert_at IS NOT NULL
                     AND CAST(strftime('%%s', 'now') AS INTEGER)
                         - CAST(strftime('%%s', last_alert_at) AS INTEGER) <= ?""",
                (staleness_threshold,),
            ).fetchone()
            active_instances = row["cnt"] if row else 0

            # Alerts in last 24 hours
            row = conn.execute(
                """SELECT COUNT(*) AS cnt FROM honeypot_alerts
                   WHERE CAST(strftime('%%s', 'now') AS INTEGER)
                         - CAST(strftime('%%s', received_at) AS INTEGER) <= 86400"""
            ).fetchone()
            alerts_24h = row["cnt"] if row else 0

            # Distinct blocked IPs
            row = conn.execute(
                "SELECT COUNT(DISTINCT ip_address) AS cnt FROM honeypot_block_entries"
            ).fetchone()
            blocked_ips = row["cnt"] if row else 0

            # Offline bundle metadata
            bundle_info = self.get_offline_bundle_info()

            return {
                "total_instances": total_instances,
                "active_instances": active_instances,
                "alerts_24h": alerts_24h,
                "blocked_ips": blocked_ips,
                "offline_bundle_available": bundle_info["available"],
                "offline_bundle_size_bytes": bundle_info["size_bytes"] if bundle_info["size_bytes"] is not None else 0,
            }

    def _row_to_instance_dict(self, row, staleness_threshold: int) -> dict:
        """Convert a database row to an instance dict with computed status.

        Args:
            row: sqlite3.Row from honeypot_instances table.
            staleness_threshold: Seconds before an instance is considered stale.

        Returns:
            Dict with instance fields and computed 'status'.
        """
        last_alert_at = row["last_alert_at"]

        if last_alert_at is None:
            status = "pending"
        else:
            # Parse the timestamp — handle both string and datetime
            if isinstance(last_alert_at, str):
                try:
                    last_alert_dt = datetime.fromisoformat(last_alert_at)
                except ValueError:
                    last_alert_dt = datetime.strptime(last_alert_at, "%Y-%m-%d %H:%M:%S")
            else:
                last_alert_dt = last_alert_at

            # Make timezone-aware if naive
            if last_alert_dt.tzinfo is None:
                last_alert_dt = last_alert_dt.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            age_seconds = (now - last_alert_dt).total_seconds()

            status = "active" if age_seconds <= staleness_threshold else "stale"

        services = row["services"]
        if isinstance(services, str):
            try:
                services = json.loads(services)
            except (json.JSONDecodeError, TypeError):
                services = []

        return {
            "id": row["id"],
            "name": row["name"],
            "ip_address": row["ip_address"],
            "services": services,
            "token_hash": row["token_hash"],
            "token_prefix": row["token_prefix"],
            "registered_at": row["registered_at"],
            "last_alert_at": last_alert_at,
            "alert_count": row["alert_count"],
            "status": status,
        }
    # Default service definitions for OpenCanary config generation
    _SERVICE_DEFAULTS = {
        "ssh": {
            "ssh.enabled": True,
            "ssh.port": 22,
            "ssh.version": "SSH-2.0-OpenSSH_5.1p1 Debian-4",
        },
        "ftp": {
            "ftp.enabled": True,
            "ftp.port": 21,
            "ftp.banner": "FTP server ready",
        },
        "http": {
            "http.enabled": True,
            "http.port": 80,
            "http.banner": "Apache/2.2.22 (Ubuntu)",
            "http.skin": "nasLogin",
        },
    }

    _DEFAULT_SERVICES = ["ssh", "ftp", "http"]

    def generate_instance_config(self, instance: dict, raw_token: str, soc_url: str) -> dict:
        """Generate an opencanary.conf dict for a specific instance.

        Args:
            instance: Instance dict from get_instance_by_token().
            raw_token: The raw API token (from the request header).
            soc_url: Base URL of the SOC server (e.g. https://soc.example.com).

        Returns:
            Dict representing the opencanary.conf JSON structure with:
            - device.node_id set to instance name
            - webhook handler URL pointing to soc_url/api/v1/honeypot/alert
            - X-Honeypot-Token header set to raw_token
            - Default service configuration based on instance services
        """
        config = {
            "device.node_id": instance.get("name", "opencanary"),
            "server.ip": "0.0.0.0",
            "ip.ignorelist": [],
            "logtype.ignorelist": [],
            "logger": {
                "class": "PyLogger",
                "kwargs": {
                    "formatters": {
                        "plain": {"format": "%(message)s"}
                    },
                    "handlers": {
                        "webhook": {
                            "class": "opencanary.logger.WebhookHandler",
                            "url": f"{soc_url}/api/v1/honeypot/alert",
                            "method": "POST",
                            "headers": {
                                "Content-Type": "application/json",
                                "X-Honeypot-Token": raw_token,
                            },
                            "status_code": 200,
                        }
                    },
                },
            },
        }

        # Determine which services to enable
        services = instance.get("services", [])
        if isinstance(services, str):
            try:
                services = json.loads(services)
            except (json.JSONDecodeError, TypeError):
                services = []

        if not services:
            services = self._DEFAULT_SERVICES

        # Add service configuration entries
        for svc in services:
            svc_lower = svc.strip().lower() if isinstance(svc, str) else str(svc).lower()
            if svc_lower in self._SERVICE_DEFAULTS:
                config.update(self._SERVICE_DEFAULTS[svc_lower])
            else:
                # For services without specific defaults, just enable them
                config[f"{svc_lower}.enabled"] = True

        return config

    # Default bundle path (matches OFFLINE_BUNDLE_PATH in honeypot_routes.py)
    _DEFAULT_BUNDLE_PATH = os.path.join("offline_bundle", "opencanary-offline.tar.gz")

    def get_offline_bundle_info(self, bundle_path: str = None) -> dict:
        """Check if the offline bundle exists and return metadata.

        Args:
            bundle_path: Path to the bundle file. Defaults to
                ``offline_bundle/opencanary-offline.tar.gz``.

        Returns:
            Dict with keys: available (bool), size_bytes (int|None),
            last_built (str ISO timestamp|None), path (str).
        """
        if bundle_path is None:
            bundle_path = self._DEFAULT_BUNDLE_PATH

        if os.path.isfile(bundle_path):
            size_bytes = os.path.getsize(bundle_path)
            mtime = os.path.getmtime(bundle_path)
            last_built = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
            return {
                "available": True,
                "size_bytes": size_bytes,
                "last_built": last_built,
                "path": bundle_path,
            }

        return {
            "available": False,
            "size_bytes": None,
            "last_built": None,
            "path": bundle_path,
        }


