"""Device manager service for CRUD operations on managed devices."""

import sqlite3
from typing import Dict, List, Optional

from database import get_db


class DeviceManager:
    """CRUD operations for managed pfSense and Linux devices."""

    def __init__(self, db_path=None):
        self.db_path = db_path

    def add_pfsense(self, hostname: str, username: str, password: str,
                    block_method: str, friendly_name: str = "") -> Dict:
        """Register a new pfSense firewall.

        Args:
            hostname: IP or hostname of the pfSense device.
            username: Web interface username.
            password: Web interface password.
            block_method: "null_route" or "floating_rule".
            friendly_name: User-friendly display name.

        Returns:
            Dict with the new device data.

        Raises:
            ValueError: If block_method is invalid.
        """
        if block_method not in ("null_route", "floating_rule"):
            raise ValueError(f"Invalid block_method: {block_method}. Must be 'null_route' or 'floating_rule'.")

        with get_db(self.db_path) as conn:
            conn.execute(
                """INSERT INTO managed_devices
                   (hostname, device_type, web_username, web_password, block_method, friendly_name)
                   VALUES (?, 'pfsense', ?, ?, ?, ?)""",
                (hostname, username, password, block_method, friendly_name),
            )
            row = conn.execute(
                "SELECT * FROM managed_devices WHERE id = last_insert_rowid()"
            ).fetchone()
            return dict(row)

    def add_linux(self, hostname: str, port: int, username: str,
                  password: Optional[str] = None,
                  key_path: Optional[str] = None,
                  friendly_name: str = "",
                  ssh_key: str = "",
                  sudo_password: str = "") -> Dict:
        """Register a new Linux device. Block method is always null_route.

        Args:
            hostname: IP or hostname of the Linux device.
            port: SSH port.
            username: SSH username.
            password: SSH password (optional).
            key_path: Path to SSH private key (optional).
            friendly_name: User-friendly display name.
            ssh_key: SSH private key content (optional).
            sudo_password: Password for sudo commands (optional, defaults to ssh password).

        Returns:
            Dict with the new device data.
        """
        with get_db(self.db_path) as conn:
            conn.execute(
                """INSERT INTO managed_devices
                   (hostname, device_type, block_method, ssh_port, ssh_username, ssh_password, ssh_key_path, friendly_name, ssh_key, sudo_password)
                   VALUES (?, 'linux', 'null_route', ?, ?, ?, ?, ?, ?, ?)""",
                (hostname, port, username, password, key_path, friendly_name, ssh_key, sudo_password),
            )
            row = conn.execute(
                "SELECT * FROM managed_devices WHERE id = last_insert_rowid()"
            ).fetchone()
            return dict(row)

    def update_device(self, device_id: int, **kwargs) -> Dict:
        """Update device configuration fields.

        Args:
            device_id: ID of the device to update.
            **kwargs: Fields to update (e.g., hostname, block_method).

        Returns:
            Dict with the updated device data.

        Raises:
            ValueError: If device not found or no fields provided.
        """
        if not kwargs:
            raise ValueError("No fields provided to update.")

        allowed = {
            "hostname", "web_username", "web_password", "block_method",
            "ssh_port", "ssh_username", "ssh_password", "ssh_key_path",
            "friendly_name", "ssh_key", "sudo_password",
        }
        invalid = set(kwargs.keys()) - allowed
        if invalid:
            raise ValueError(f"Invalid fields: {invalid}")

        set_clause = ", ".join(f"{k} = ?" for k in kwargs)
        values = list(kwargs.values()) + [device_id]

        with get_db(self.db_path) as conn:
            cursor = conn.execute(
                f"UPDATE managed_devices SET {set_clause} WHERE id = ?",
                values,
            )
            if cursor.rowcount == 0:
                raise ValueError(f"Device with id {device_id} not found.")

            row = conn.execute(
                "SELECT * FROM managed_devices WHERE id = ?", (device_id,)
            ).fetchone()
            return dict(row)

    def remove_device(self, device_id: int) -> None:
        """Remove a device from the registry.

        Args:
            device_id: ID of the device to remove.

        Raises:
            ValueError: If device not found.
        """
        with get_db(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM managed_devices WHERE id = ?", (device_id,)
            )
            if cursor.rowcount == 0:
                raise ValueError(f"Device with id {device_id} not found.")

    def get_all_devices(self) -> List[Dict]:
        """Return all registered devices.

        Returns:
            List of dicts with device data.
        """
        with get_db(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM managed_devices ORDER BY id"
            ).fetchall()
            return [dict(r) for r in rows]

    def get_devices_by_type(self, device_type: str) -> List[Dict]:
        """Return devices filtered by type.

        Args:
            device_type: "pfsense" or "linux".

        Returns:
            List of dicts with device data.
        """
        with get_db(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM managed_devices WHERE device_type = ? ORDER BY id",
                (device_type,),
            ).fetchall()
            return [dict(r) for r in rows]
