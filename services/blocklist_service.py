"""Blocklist service for managing the central IP blocklist."""

import ipaddress
import sqlite3
from typing import Dict, List, Tuple

from database import get_db


class BlocklistService:
    """Core business logic for managing the central IP blocklist."""

    def __init__(self, db_path=None):
        self.db_path = db_path

    def validate_ip(self, ip_address: str) -> Tuple[bool, str]:
        """Validate IPv4/IPv6 address or CIDR network notation.

        Accepts:
            - Single IPs: 10.0.0.1 (treated as /32)
            - CIDR notation: 10.0.0.0/24

        Args:
            ip_address: String to validate as an IP address or CIDR network.

        Returns:
            Tuple of (is_valid, error_message). error_message is empty if valid.
        """
        try:
            addr = ip_address.strip()
            if "/" in addr:
                ipaddress.ip_network(addr, strict=False)
            else:
                ipaddress.ip_address(addr)
            return (True, "")
        except ValueError as e:
            return (False, str(e))

    def add_ip(self, ip_address: str, user: str, note: str = "") -> Dict:
        """Validate and add an IP to the blocklist.

        Args:
            ip_address: IPv4 or IPv6 address to block.
            user: Username of the person adding the block.
            note: Optional note for the entry.

        Returns:
            Dict with the new block entry data.

        Raises:
            ValueError: If IP is invalid, already exists, or falls within a protected range.
        """
        ip_str = ip_address.strip()
        valid, error_msg = self.validate_ip(ip_str)
        if not valid:
            raise ValueError(f"Invalid IP address: {error_msg}")

        # Normalize: always store with CIDR suffix
        if "/" in ip_str:
            network = ipaddress.ip_network(ip_str, strict=False)
            normalized = str(network)
        else:
            normalized = str(ipaddress.ip_address(ip_str)) + "/32"

        # Check against protected ranges
        self._check_protected_ranges(normalized)

        with get_db(self.db_path) as conn:
            # Check for duplicate
            existing = conn.execute(
                "SELECT id FROM block_entries WHERE ip_address = ?",
                (normalized,),
            ).fetchone()
            if existing:
                raise ValueError(f"IP address {normalized} is already in the blocklist")

            conn.execute(
                "INSERT INTO block_entries (ip_address, added_by, note) VALUES (?, ?, ?)",
                (normalized, user, note),
            )
            row = conn.execute(
                "SELECT id, ip_address, added_by, added_at, note FROM block_entries WHERE ip_address = ?",
                (normalized,),
            ).fetchone()

        return dict(row)

    def _check_protected_ranges(self, normalized_ip: str) -> None:
        """Check if an IP/CIDR falls within any protected range.

        Args:
            normalized_ip: Normalized IP with CIDR suffix (e.g. '10.0.1.2/32').

        Raises:
            ValueError: If the IP overlaps with a protected range.
        """
        with get_db(self.db_path) as conn:
            row = conn.execute(
                "SELECT protected_ranges FROM app_settings WHERE id = 1"
            ).fetchone()
            if not row or not row["protected_ranges"]:
                return

            protected_str = row["protected_ranges"].strip()
            if not protected_str:
                return

            try:
                target = ipaddress.ip_network(normalized_ip, strict=False)
            except ValueError:
                return

            for line in protected_str.split("\n"):
                range_str = line.strip()
                if not range_str:
                    continue
                try:
                    protected_net = ipaddress.ip_network(range_str, strict=False)
                    # Check if target overlaps with protected range
                    if target.overlaps(protected_net):
                        raise ValueError(
                            f"IP {normalized_ip} is within protected range {protected_net}"
                        )
                except ValueError as e:
                    if "protected range" in str(e):
                        raise
                    # Skip malformed entries
                    continue

    def remove_ip(self, ip_address: str) -> None:
        """Remove an IP from the blocklist. Cascade deletes push_statuses.

        Args:
            ip_address: IPv4 or IPv6 address to remove.

        Raises:
            ValueError: If IP is not found in the blocklist.
        """
        ip_str = ip_address.strip()
        with get_db(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM block_entries WHERE ip_address = ?",
                (ip_str,),
            ).fetchone()
            if not existing:
                raise ValueError(f"IP address {ip_str} not found in the blocklist")

            conn.execute(
                "DELETE FROM block_entries WHERE ip_address = ?",
                (ip_str,),
            )

    def get_blocklist(self) -> List[Dict]:
        """Return all current blocklist entries with push status.

        Returns:
            List of dicts, each with block entry fields and a push_statuses list.
        """
        with get_db(self.db_path) as conn:
            entries = conn.execute(
                "SELECT id, ip_address, added_by, added_at, note FROM block_entries ORDER BY added_at DESC"
            ).fetchall()

            result = []
            for entry in entries:
                entry_dict = dict(entry)
                statuses = conn.execute(
                    """SELECT ps.id, ps.device_id, ps.status, ps.error_message, ps.pushed_at,
                              md.hostname, md.device_type, md.friendly_name
                       FROM push_statuses ps
                       JOIN managed_devices md ON ps.device_id = md.id
                       WHERE ps.block_entry_id = ?""",
                    (entry_dict["id"],),
                ).fetchall()
                entry_dict["push_statuses"] = [dict(s) for s in statuses]
                result.append(entry_dict)

            return result
