"""Push engine for concurrent IP block/unblock operations across managed devices."""

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

from clients.linux_client import LinuxClient
from clients.pfsense_client import PfSenseClient
from database import get_db

logger = logging.getLogger(__name__)

PFSENSE_ALIAS_NAME = "soc_blocklist"


class PushEngine:
    """Handles concurrent push/removal of IP blocks to all managed devices."""

    def __init__(self, db_path=None):
        self.db_path = db_path

    def _get_block_entry_id(self, conn, ip_address: str) -> Optional[int]:
        """Look up the block_entry id for an IP address."""
        row = conn.execute(
            "SELECT id FROM block_entries WHERE ip_address = ?",
            (ip_address,),
        ).fetchone()
        return row["id"] if row else None
    def _get_all_blocked_ips(self) -> list:
        """Return all blocked IP addresses from the database."""
        with get_db(self.db_path) as conn:
            rows = conn.execute(
                "SELECT ip_address FROM block_entries ORDER BY id"
            ).fetchall()
            return [row["ip_address"] for row in rows]

    def _push_to_device(self, ip_address: str, device: Dict, action: str) -> Dict:
        """Push a block or removal to a single device.

        Args:
            ip_address: The IP to block/unblock.
            device: Device dict from DeviceManager.get_all_devices().
            action: "block" or "remove".

        Returns:
            PushResult dict with device_id, success, error_message.
        """
        device_id = device["id"]
        try:
            if device["device_type"] == "pfsense":
                client = PfSenseClient(
                    host=device["hostname"],
                    username=device["web_username"],
                    password=device["web_password"],
                )
                if action == "block":
                    if device.get("block_method") == "floating_rule":
                        # Rewrite entire alias from DB to preserve CIDR masks.
                        # pfSense ignores address_subnet POST values, so
                        # incremental add/remove corrupts existing entries.
                        all_ips = self._get_all_blocked_ips()
                        client.ensure_alias_exists(PFSENSE_ALIAS_NAME, all_ips)
                    else:
                        client.add_null_route(ip_address)
                else:
                    if device.get("block_method") == "floating_rule":
                        # Rewrite entire alias from DB (IP already removed from DB)
                        all_ips = self._get_all_blocked_ips()
                        client.ensure_alias_exists(PFSENSE_ALIAS_NAME, all_ips)
                    else:
                        client.remove_null_route(ip_address)

            elif device["device_type"] == "linux":
                client = LinuxClient(
                    host=device["hostname"],
                    port=device.get("ssh_port", 22),
                    username=device["ssh_username"],
                    password=device.get("ssh_password"),
                    key_path=device.get("ssh_key_path"),
                    key_content=device.get("ssh_key"),
                    sudo_password=device.get("sudo_password"),
                )
                if action == "block":
                    client.add_null_route(ip_address)
                else:
                    client.remove_null_route(ip_address)
            else:
                raise ValueError(f"Unknown device type: {device['device_type']}")

            return {"device_id": device_id, "success": True, "error_message": None}

        except Exception as e:
            logger.error(
                "Failed to %s %s on device %s (%s): %s",
                action, ip_address, device_id, device["hostname"], e,
            )
            return {"device_id": device_id, "success": False, "error_message": str(e)}

    def _store_push_statuses(self, block_entry_id: int, results: List[Dict]) -> None:
        """Persist push results to the database."""
        with get_db(self.db_path) as conn:
            for r in results:
                status = "success" if r["success"] else "failed"
                conn.execute(
                    """INSERT OR REPLACE INTO push_statuses
                       (block_entry_id, device_id, status, error_message, pushed_at)
                       VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)""",
                    (block_entry_id, r["device_id"], status, r["error_message"]),
                )

    def push_block(self, ip_address: str, devices: List[Dict]) -> List[Dict]:
        """Push an IP block to all given devices concurrently.

        Args:
            ip_address: The IP address to block.
            devices: List of device dicts from DeviceManager.get_all_devices().

        Returns:
            List of PushResult dicts.
        """
        if not devices:
            return []

        with ThreadPoolExecutor() as executor:
            futures = [
                executor.submit(self._push_to_device, ip_address, dev, "block")
                for dev in devices
            ]
            results = [f.result() for f in futures]

        with get_db(self.db_path) as conn:
            block_entry_id = self._get_block_entry_id(conn, ip_address)

        if block_entry_id is not None:
            self._store_push_statuses(block_entry_id, results)

        return results

    def remove_block(self, ip_address: str, devices: List[Dict], block_entry_id: int = None) -> List[Dict]:
        """Remove an IP block from all given devices concurrently.

        Args:
            ip_address: The IP address to unblock.
            devices: List of device dicts from DeviceManager.get_all_devices().
            block_entry_id: Optional pre-fetched block entry ID for status tracking.

        Returns:
            List of PushResult dicts.
        """
        if not devices:
            return []

        # Use provided block_entry_id or try to look it up
        if block_entry_id is None:
            with get_db(self.db_path) as conn:
                block_entry_id = self._get_block_entry_id(conn, ip_address)

        with ThreadPoolExecutor() as executor:
            futures = [
                executor.submit(self._push_to_device, ip_address, dev, "remove")
                for dev in devices
            ]
            results = [f.result() for f in futures]

        if block_entry_id is not None:
            self._store_push_statuses(block_entry_id, results)

        return results
