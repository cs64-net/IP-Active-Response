"""Reconciliation engine for detecting and correcting drift between desired and actual device state."""

import json
import logging
import uuid

from database import get_db
from services.rules_engine import _write_audit_log

logger = logging.getLogger(__name__)

PFSENSE_ALIAS_NAME = "soc_blocklist"


class ReconciliationEngine:
    """Compares desired blocklist state against actual device state and enqueues corrections."""

    def __init__(self, db_path=None):
        self.db_path = db_path

    def get_desired_state(self) -> set:
        """Read block_entries table and return the set of IP strings.

        Returns:
            Set of IP address strings from the blocklist.
        """
        with get_db(self.db_path) as conn:
            rows = conn.execute("SELECT ip_address FROM block_entries").fetchall()
            return {row["ip_address"] for row in rows}

    def get_actual_state(self, device: dict) -> set:
        """Query a device for its currently applied rules.

        Routes to the appropriate client method based on device_type and block_method.

        Args:
            device: Device dict with keys including device_type, block_method,
                    hostname, and connection credentials.

        Returns:
            Set of IP/CIDR strings currently applied on the device.

        Raises:
            ValueError: If device_type or block_method is unsupported.
        """
        device_type = device.get("device_type")
        block_method = device.get("block_method")

        if device_type == "linux" and block_method == "null_route":
            from clients.linux_client import LinuxClient

            client = LinuxClient(
                host=device["hostname"],
                port=device.get("ssh_port", 22) or 22,
                username=device.get("ssh_username", ""),
                password=device.get("ssh_password"),
                key_path=device.get("ssh_key_path"),
                key_content=device.get("ssh_key"),
                sudo_password=device.get("sudo_password"),
            )
            return client.get_blackhole_routes()

        elif device_type == "pfsense" and block_method == "null_route":
            from clients.pfsense_client import PfSenseClient

            client = PfSenseClient(
                host=device["hostname"],
                username=device.get("web_username", ""),
                password=device.get("web_password", ""),
            )
            return client.get_static_routes()

        elif device_type == "pfsense" and block_method == "floating_rule":
            from clients.pfsense_client import PfSenseClient

            client = PfSenseClient(
                host=device["hostname"],
                username=device.get("web_username", ""),
                password=device.get("web_password", ""),
            )
            return client.get_alias_entries(PFSENSE_ALIAS_NAME)

        else:
            raise ValueError(
                f"Unsupported device_type/block_method combination: "
                f"{device_type}/{block_method}"
            )

    def compute_drift(self, desired: set, actual: set) -> dict:
        """Compute the drift between desired and actual state.

        Args:
            desired: Set of IP strings that should be on the device.
            actual: Set of IP strings currently on the device.

        Returns:
            Dict with "missing" (IPs in desired but not actual) and
            "extraneous" (IPs in actual but not desired) as sets.
        """
        return {
            "missing": desired - actual,
            "extraneous": actual - desired,
        }

    def run_reconciliation(self) -> dict:
        """Check all online devices for drift and enqueue corrective operations.

        Iterates all managed devices with status 'online', queries each for its
        actual state, compares against the desired state from block_entries, and
        enqueues corrective add/remove operations for any drift detected.

        Returns:
            Summary dict with devices_checked, drift_events, and corrective_ops counts.
        """
        desired = self.get_desired_state()

        devices_checked = 0
        drift_events = 0
        corrective_ops = 0

        with get_db(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM managed_devices WHERE status = 'online'"
            ).fetchall()
            devices = [dict(row) for row in rows]

        for device in devices:
            device_id = device["id"]
            devices_checked += 1

            try:
                actual = self.get_actual_state(device)
            except Exception as exc:
                logger.warning(
                    "Reconciliation: unable to query device %s (%s): %s",
                    device_id,
                    device.get("hostname", "unknown"),
                    exc,
                )
                continue

            drift = self.compute_drift(desired, actual)
            missing = drift["missing"]
            extraneous = drift["extraneous"]

            if not missing and not extraneous:
                continue

            drift_events += 1

            with get_db(self.db_path) as conn:
                if missing:
                    op_id = str(uuid.uuid4())
                    conn.execute(
                        "INSERT INTO operation_queue "
                        "(operation_id, device_id, action, ip_addresses, source) "
                        "VALUES (?, ?, 'add', ?, 'reconciliation')",
                        (op_id, device_id, json.dumps(sorted(missing))),
                    )
                    corrective_ops += 1

                if extraneous:
                    op_id = str(uuid.uuid4())
                    conn.execute(
                        "INSERT INTO operation_queue "
                        "(operation_id, device_id, action, ip_addresses, source) "
                        "VALUES (?, ?, 'remove', ?, 'reconciliation')",
                        (op_id, device_id, json.dumps(sorted(extraneous))),
                    )
                    corrective_ops += 1

                conn.execute(
                    "INSERT INTO audit_log "
                    "(event_type, action, device_id, details) "
                    "VALUES ('reconciliation', 'drift detected', ?, ?)",
                    (
                        device_id,
                        json.dumps({
                            "missing_count": len(missing),
                            "extraneous_count": len(extraneous),
                        }),
                    ),
                )

        logger.info(
            "Reconciliation complete: %d devices checked, %d drift events, %d corrective ops",
            devices_checked,
            drift_events,
            corrective_ops,
        )

        _write_audit_log(
            self.db_path,
            event_type="reconciliation",
            action="reconciliation completed",
            details={
                "devices_checked": devices_checked,
                "drift_events": drift_events,
                "corrective_ops": corrective_ops,
            },
        )

        return {
            "devices_checked": devices_checked,
            "drift_events": drift_events,
            "corrective_ops": corrective_ops,
        }
