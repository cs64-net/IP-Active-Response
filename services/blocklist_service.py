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
            addr = ipaddress.ip_address(ip_str)
            suffix = "/128" if isinstance(addr, ipaddress.IPv6Address) else "/32"
            normalized = str(addr) + suffix

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

    def add_ips_bulk(self, ip_addresses: List[str], user: str, note: str = "",
                     skip_invalid: bool = False) -> Dict:
        """Validate and add multiple IPs to the blocklist.

        By default (skip_invalid=False) the batch is all-or-nothing: if any IP
        is invalid, duplicated, already blocked, or in a protected range the
        entire batch is rejected.

        When skip_invalid=True (used by feed syncs), bad IPs are silently
        filtered out and the remaining valid IPs are inserted.  Skipped IPs
        are reported in the returned ``skipped`` list for logging.

        Args:
            ip_addresses: List of IPv4/IPv6 addresses or CIDR notations to block.
            user: Username of the person adding the blocks.
            note: Optional note for the entries.
            skip_invalid: If True, skip bad IPs instead of rejecting the batch.

        Returns:
            Dict with "added" (list of added IP dicts), "errors" (list of error
            strings), and "skipped" (list of skipped IP strings, only when
            skip_invalid=True).
        """
        errors = []
        skipped = []
        normalized_ips = []

        # Phase 1: Validate all IPs and normalize
        for ip in ip_addresses:
            ip_str = ip.strip()
            valid, error_msg = self.validate_ip(ip_str)
            if not valid:
                if skip_invalid:
                    skipped.append(ip_str)
                    continue
                errors.append(f"Invalid IP address '{ip_str}': {error_msg}")
                continue

            if "/" in ip_str:
                network = ipaddress.ip_network(ip_str, strict=False)
                normalized = str(network)
            else:
                addr = ipaddress.ip_address(ip_str)
                suffix = "/128" if isinstance(addr, ipaddress.IPv6Address) else "/32"
                normalized = str(addr) + suffix

            normalized_ips.append(normalized)

        # Phase 2: Check for duplicates within the batch
        seen = set()
        deduped = []
        for norm_ip in normalized_ips:
            if norm_ip in seen:
                if skip_invalid:
                    skipped.append(norm_ip)
                else:
                    errors.append(f"Duplicate IP in batch: {norm_ip}")
            else:
                seen.add(norm_ip)
                deduped.append(norm_ip)
        normalized_ips = deduped

        # Phase 3: Check protected ranges (before opening DB transaction)
        if skip_invalid:
            filtered = []
            for norm_ip in normalized_ips:
                try:
                    self._check_protected_ranges(norm_ip)
                    filtered.append(norm_ip)
                except ValueError:
                    skipped.append(norm_ip)
            normalized_ips = filtered
        else:
            for norm_ip in normalized_ips:
                try:
                    self._check_protected_ranges(norm_ip)
                except ValueError as e:
                    errors.append(str(e))

        # Phase 4: Check for existing entries in DB
        if skip_invalid:
            filtered = []
            with get_db(self.db_path) as conn:
                for norm_ip in normalized_ips:
                    existing = conn.execute(
                        "SELECT id FROM block_entries WHERE ip_address = ?",
                        (norm_ip,),
                    ).fetchone()
                    if existing:
                        skipped.append(norm_ip)
                    else:
                        filtered.append(norm_ip)
            normalized_ips = filtered
        else:
            if not errors:
                with get_db(self.db_path) as conn:
                    for norm_ip in normalized_ips:
                        existing = conn.execute(
                            "SELECT id FROM block_entries WHERE ip_address = ?",
                            (norm_ip,),
                        ).fetchone()
                        if existing:
                            errors.append(
                                f"IP address {norm_ip} is already in the blocklist"
                            )

        # All-or-nothing when not skipping: if any errors, reject entire batch
        if not skip_invalid and errors:
            return {"added": [], "errors": errors, "skipped": []}

        if not normalized_ips:
            return {"added": [], "errors": errors, "skipped": skipped}

        # Phase 5: Insert all valid IPs in a single transaction
        added = []
        with get_db(self.db_path) as conn:
            for norm_ip in normalized_ips:
                conn.execute(
                    "INSERT INTO block_entries (ip_address, added_by, note) VALUES (?, ?, ?)",
                    (norm_ip, user, note),
                )
                row = conn.execute(
                    "SELECT id, ip_address, added_by, added_at, note FROM block_entries WHERE ip_address = ?",
                    (norm_ip,),
                ).fetchone()
                added.append(dict(row))

        return {"added": added, "errors": errors, "skipped": skipped}


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

        # Normalize to match stored form
        if "/" in ip_str:
            network = ipaddress.ip_network(ip_str, strict=False)
            normalized = str(network)
        else:
            addr = ipaddress.ip_address(ip_str)
            suffix = "/128" if isinstance(addr, ipaddress.IPv6Address) else "/32"
            normalized = str(addr) + suffix

        with get_db(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM block_entries WHERE ip_address = ?",
                (normalized,),
            ).fetchone()
            if not existing:
                raise ValueError(f"IP address {normalized} not found in the blocklist")

            conn.execute(
                "DELETE FROM block_entries WHERE ip_address = ?",
                (normalized,),
            )

    def remove_ips_bulk(self, ip_addresses: List[str]) -> Dict:
        """Remove multiple IPs from the blocklist atomically in a single transaction.

        All specified IPs are normalized and removed in one transaction.
        IPs that don't exist in the blocklist are silently skipped (not treated as errors).
        Associated push_statuses are cascade-deleted via foreign key constraint.

        Args:
            ip_addresses: List of IPv4/IPv6 addresses or CIDR notations to remove.

        Returns:
            Dict with "removed" (list of IP strings removed) and "errors" (list of error strings).
        """
        errors = []
        normalized_ips = []

        # Phase 1: Validate and normalize all IPs
        for ip in ip_addresses:
            ip_str = ip.strip()
            valid, error_msg = self.validate_ip(ip_str)
            if not valid:
                errors.append(f"Invalid IP address '{ip_str}': {error_msg}")
                continue

            if "/" in ip_str:
                network = ipaddress.ip_network(ip_str, strict=False)
                normalized = str(network)
            else:
                addr = ipaddress.ip_address(ip_str)
                suffix = "/128" if isinstance(addr, ipaddress.IPv6Address) else "/32"
                normalized = str(addr) + suffix

            normalized_ips.append(normalized)

        if errors:
            return {"removed": [], "errors": errors}

        # Phase 2: Remove all IPs in a single transaction (atomic)
        removed = []
        with get_db(self.db_path) as conn:
            for norm_ip in normalized_ips:
                existing = conn.execute(
                    "SELECT id FROM block_entries WHERE ip_address = ?",
                    (norm_ip,),
                ).fetchone()
                if existing:
                    conn.execute(
                        "DELETE FROM block_entries WHERE ip_address = ?",
                        (norm_ip,),
                    )
                    removed.append(norm_ip)
                # Non-existent IPs are silently skipped

        return {"removed": removed, "errors": []}



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
