"""DNS block manager for domain-based IP blocking.

Orchestrates DNS block entry CRUD, input validation, DNS lookups via dig,
diff synchronization, and coordination with the RulesEngine to maintain
the central blocklist. Follows the FeedManager pattern.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import shutil
import subprocess
import time

from database import get_db
from services.rules_engine import RulesEngine, _write_audit_log

logger = logging.getLogger(__name__)


class DNSBlockManager:
    """Manages DNS block entries: CRUD, DNS lookups, diff sync, and blocklist coordination."""

    MAX_CONCURRENT_LOOKUPS = 5
    DIG_TIMEOUT = 10
    CONSECUTIVE_FAILURE_THRESHOLD = 3

    def __init__(self, db_path: str = None):
        """Initialize with database path.

        Args:
            db_path: Path to the SQLite database file. Defaults to Config.DATABASE_PATH.
        """
        self.db_path = db_path
        self.rules_engine = RulesEngine(db_path=db_path)

    def _validate_domain(self, domain: str) -> bool:
        """Validate domain name syntax per RFC 1035.

        Rules:
        - Total length <= 253 characters
        - Each label 1-63 characters
        - Labels contain only alphanumeric characters and hyphens
        - Labels do not start or end with a hyphen
        - At least two labels (e.g. example.com)

        Args:
            domain: Domain name string to validate.

        Returns:
            True if valid, False otherwise.
        """
        if not domain or not isinstance(domain, str):
            return False

        # Strip trailing dot if present (FQDN notation)
        if domain.endswith("."):
            domain = domain[:-1]

        if not domain:
            return False

        if len(domain) > 253:
            return False

        labels = domain.split(".")
        if len(labels) < 2:
            return False

        # RFC 1035 label pattern: alphanumeric, hyphens allowed in middle
        label_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')

        for label in labels:
            if not label or len(label) > 63:
                return False
            if not label_pattern.match(label):
                return False

        return True

    def _validate_dns_server(self, dns_server: str) -> bool:
        """Validate DNS server is a valid IPv4 or IPv6 address.

        Args:
            dns_server: IP address string to validate.

        Returns:
            True if valid IPv4 or IPv6, False otherwise.
        """
        if not dns_server or not isinstance(dns_server, str):
            return False
        try:
            ipaddress.ip_address(dns_server)
            return True
        except (ValueError, TypeError):
            return False

    def _validate_refresh_interval(self, interval: int) -> bool:
        """Validate refresh interval is between 30 and 86400 seconds.

        Args:
            interval: Refresh interval in seconds.

        Returns:
            True if valid, False otherwise.
        """
        if not isinstance(interval, int) or isinstance(interval, bool):
            return False
        return 30 <= interval <= 86400

    def create_entry(self, domain: str, dns_server: str, refresh_interval: int,
                     stale_cleanup: bool = False, enabled: bool = True) -> dict:
        """Validate inputs, create DB record, run initial lookup, return entry dict.

        Args:
            domain: Domain name to resolve.
            dns_server: DNS server IP address.
            refresh_interval: Refresh interval in seconds (30-86400).
            stale_cleanup: Whether to remove stale IPs on refresh.
            enabled: Whether the entry is active.

        Returns:
            Dict representing the created DNS block entry.

        Raises:
            ValueError: On validation failure or duplicate domain.
        """
        # Validate inputs
        if not self._validate_domain(domain):
            raise ValueError(
                f"Invalid domain name '{domain}'. Must be a valid DNS name "
                f"(RFC 1035: labels 1-63 chars, alphanumeric and hyphens, "
                f"at least two labels, total <= 253 chars)."
            )

        if not self._validate_dns_server(dns_server):
            raise ValueError(
                f"Invalid DNS server address '{dns_server}'. "
                f"Must be a valid IPv4 or IPv6 address."
            )

        if not self._validate_refresh_interval(refresh_interval):
            raise ValueError(
                f"Invalid refresh interval {refresh_interval}. "
                f"Must be an integer between 30 and 86400 seconds."
            )

        # Check for duplicate domain
        with get_db(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM dns_block_entries WHERE domain = ?",
                (domain,),
            ).fetchone()
            if existing:
                raise ValueError(
                    f"A DNS block entry for domain '{domain}' already exists."
                )

            # Insert the entry
            cursor = conn.execute(
                """INSERT INTO dns_block_entries
                   (domain, dns_server, refresh_interval, stale_cleanup, enabled)
                   VALUES (?, ?, ?, ?, ?)""",
                (domain, dns_server, refresh_interval,
                 1 if stale_cleanup else 0, 1 if enabled else 0),
            )
            entry_id = cursor.lastrowid

        # Write audit log
        _write_audit_log(
            self.db_path,
            event_type="dns_block_management",
            action=f"DNS block entry '{domain}' created",
            details={
                "entry_id": entry_id,
                "domain": domain,
                "dns_server": dns_server,
                "refresh_interval": refresh_interval,
                "stale_cleanup": stale_cleanup,
                "enabled": enabled,
            },
        )

        logger.info(
            "Created DNS block entry '%s' (id=%d, server=%s, interval=%ds)",
            domain, entry_id, dns_server, refresh_interval,
        )

        # Run initial DNS lookup
        try:
            self.refresh_entry(entry_id, trigger="initial")
        except Exception as e:
            logger.warning(
                "Initial DNS lookup failed for '%s': %s", domain, e,
            )

        return self._entry_to_dict(entry_id)

    def update_entry(self, entry_id: int, **kwargs) -> dict:
        """Update mutable fields (dns_server, refresh_interval, stale_cleanup, enabled).

        Rejects domain changes. Only updates fields that are provided.

        Args:
            entry_id: The database ID of the entry to update.
            **kwargs: Fields to update. Supported: dns_server, refresh_interval,
                      stale_cleanup, enabled.

        Returns:
            Dict representing the updated entry.

        Raises:
            ValueError: If entry not found, domain change attempted, or validation fails.
        """
        # Reject domain changes
        if "domain" in kwargs:
            raise ValueError(
                "Domain name cannot be changed. Delete this entry and create a new one."
            )

        allowed_fields = {"dns_server", "refresh_interval", "stale_cleanup", "enabled"}
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if not updates:
            raise ValueError("No valid fields to update")

        # Validate fields if provided
        if "dns_server" in updates:
            if not self._validate_dns_server(updates["dns_server"]):
                raise ValueError(
                    f"Invalid DNS server address '{updates['dns_server']}'. "
                    f"Must be a valid IPv4 or IPv6 address."
                )

        if "refresh_interval" in updates:
            if not self._validate_refresh_interval(updates["refresh_interval"]):
                raise ValueError(
                    f"Invalid refresh interval {updates['refresh_interval']}. "
                    f"Must be an integer between 30 and 86400 seconds."
                )

        with get_db(self.db_path) as conn:
            existing = conn.execute(
                "SELECT * FROM dns_block_entries WHERE id = ?", (entry_id,)
            ).fetchone()
            if not existing:
                raise ValueError(f"DNS block entry with id {entry_id} not found")

            # Convert booleans to int for SQLite
            if "stale_cleanup" in updates:
                updates["stale_cleanup"] = 1 if updates["stale_cleanup"] else 0
            if "enabled" in updates:
                updates["enabled"] = 1 if updates["enabled"] else 0

            # Build and execute UPDATE
            set_clause = ", ".join(f"{k} = ?" for k in updates)
            set_clause += ", updated_at = CURRENT_TIMESTAMP"
            values = list(updates.values()) + [entry_id]
            conn.execute(
                f"UPDATE dns_block_entries SET {set_clause} WHERE id = ?",
                values,
            )

        _write_audit_log(
            self.db_path,
            event_type="dns_block_management",
            action=f"DNS block entry id={entry_id} updated",
            details={
                "entry_id": entry_id,
                "updates": {k: v for k, v in kwargs.items() if k in allowed_fields},
            },
        )

        logger.info("Updated DNS block entry id=%d: %s", entry_id, updates)
        return self._entry_to_dict(entry_id)

    def delete_entry(self, entry_id: int) -> None:
        """Delete entry, remove exclusive IPs from blocklist, clean up dns_resolved_ips.

        Checks each resolved IP for cross-references before removing from the
        central blocklist. The CASCADE delete on dns_resolved_ips handles
        cleanup of resolved IP records.

        Args:
            entry_id: The database ID of the entry to delete.

        Raises:
            ValueError: If the entry is not found.
        """
        with get_db(self.db_path) as conn:
            entry = conn.execute(
                "SELECT * FROM dns_block_entries WHERE id = ?", (entry_id,)
            ).fetchone()
            if not entry:
                raise ValueError(f"DNS block entry with id {entry_id} not found")
            domain = entry["domain"]

        # Get resolved IPs for this entry and find exclusive ones
        resolved_ips = self._get_resolved_ips(entry_id)
        exclusive_ips = [
            ip for ip in resolved_ips
            if self._is_ip_exclusive(ip, entry_id)
        ]

        # Remove exclusive IPs from blocklist via RulesEngine
        if exclusive_ips:
            added_by = f"dns:{domain}"
            try:
                self.rules_engine.process_unblock(exclusive_ips, added_by)
            except Exception as e:
                logger.error(
                    "Error removing exclusive IPs for deleted DNS entry '%s': %s",
                    domain, e,
                )

        # Delete the entry (CASCADE removes dns_resolved_ips)
        with get_db(self.db_path) as conn:
            conn.execute(
                "DELETE FROM dns_block_entries WHERE id = ?", (entry_id,)
            )

        _write_audit_log(
            self.db_path,
            event_type="dns_block_management",
            action=f"DNS block entry '{domain}' deleted",
            details={
                "entry_id": entry_id,
                "domain": domain,
                "exclusive_ips_removed": len(exclusive_ips),
            },
        )

        logger.info(
            "Deleted DNS block entry '%s' (id=%d), removed %d exclusive IPs",
            domain, entry_id, len(exclusive_ips),
        )

    def get_entry(self, entry_id: int) -> dict:
        """Return entry dict by ID.

        Args:
            entry_id: The database ID of the entry.

        Returns:
            Dict representing the DNS block entry.

        Raises:
            ValueError: If the entry is not found.
        """
        with get_db(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM dns_block_entries WHERE id = ?", (entry_id,)
            ).fetchone()
            if not row:
                raise ValueError(f"DNS block entry with id {entry_id} not found")
            return dict(row)

    def get_all_entries(self) -> list[dict]:
        """Return all DNS block entries as dicts.

        Returns:
            List of dicts representing all DNS block entries, ordered by creation time.
        """
        with get_db(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM dns_block_entries ORDER BY created_at DESC"
            ).fetchall()
            return [dict(row) for row in rows]

    def toggle_entry(self, entry_id: int, enabled: bool) -> None:
        """Set enabled state for a DNS block entry.

        Args:
            entry_id: The database ID of the entry.
            enabled: True to enable, False to disable.

        Raises:
            ValueError: If the entry is not found.
        """
        with get_db(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM dns_block_entries WHERE id = ?", (entry_id,)
            ).fetchone()
            if not existing:
                raise ValueError(f"DNS block entry with id {entry_id} not found")

            conn.execute(
                "UPDATE dns_block_entries SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (1 if enabled else 0, entry_id),
            )

        state_str = "enabled" if enabled else "disabled"
        _write_audit_log(
            self.db_path,
            event_type="dns_block_management",
            action=f"DNS block entry id={entry_id} {state_str}",
            details={"entry_id": entry_id, "enabled": enabled},
        )

        logger.info("DNS block entry id=%d %s", entry_id, state_str)

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    def _entry_to_dict(self, entry_id: int) -> dict:
        """Load a DNS block entry record as a dict.

        Args:
            entry_id: The database ID of the entry.

        Returns:
            Dict representing the entry.

        Raises:
            ValueError: If the entry is not found.
        """
        with get_db(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM dns_block_entries WHERE id = ?", (entry_id,)
            ).fetchone()
            if not row:
                raise ValueError(f"DNS block entry with id {entry_id} not found")
            return dict(row)

    def _get_resolved_ips(self, entry_id: int) -> list[str]:
        """Get all resolved IP addresses for a DNS block entry.

        Args:
            entry_id: The database ID of the entry.

        Returns:
            List of IP address strings.
        """
        with get_db(self.db_path) as conn:
            rows = conn.execute(
                "SELECT ip_address FROM dns_resolved_ips WHERE dns_block_entry_id = ?",
                (entry_id,),
            ).fetchall()
            return [row["ip_address"] for row in rows]

    def _is_ip_exclusive(self, ip: str, entry_id: int) -> bool:
        """Check if IP is only referenced by this DNS block entry.

        An IP is exclusive if:
        1. No other dns_resolved_ips rows exist for that IP with a different entry_id
        2. No feed_entries rows exist for that IP
        3. The IP is not in block_entries with added_by NOT starting with 'dns:'
           (i.e., not manually added or added by a feed)

        Args:
            ip: The IP address to check.
            entry_id: The DNS block entry ID to check exclusivity against.

        Returns:
            True if the IP is exclusive to this entry, False otherwise.
        """
        with get_db(self.db_path) as conn:
            # Check if any other DNS block entry has this IP
            other_dns = conn.execute(
                "SELECT 1 FROM dns_resolved_ips WHERE ip_address = ? AND dns_block_entry_id != ? LIMIT 1",
                (ip, entry_id),
            ).fetchone()
            if other_dns:
                return False

            # Check if any feed has this IP
            feed_ref = conn.execute(
                "SELECT 1 FROM feed_entries WHERE ip_address = ? LIMIT 1",
                (ip,),
            ).fetchone()
            if feed_ref:
                return False

            # Check if the IP was added by a non-DNS source
            manual_entry = conn.execute(
                "SELECT 1 FROM block_entries WHERE ip_address = ? AND added_by NOT LIKE 'dns:%' LIMIT 1",
                (ip,),
            ).fetchone()
            if manual_entry:
                return False

            return True

    # ------------------------------------------------------------------
    # DNS lookup and diff sync methods
    # ------------------------------------------------------------------

    @staticmethod
    def _dig_path() -> str:
        """Locate the dig binary, checking PATH and common install locations."""
        path = shutil.which("dig")
        if path:
            return path
        # Common locations on Debian/Alpine containers
        for candidate in ("/usr/bin/dig", "/usr/local/bin/dig"):
            if shutil.which(candidate):
                return candidate
        raise FileNotFoundError(
            "'dig' command not found. Install dnsutils (Debian/Ubuntu) "
            "or bind-tools (Alpine) to enable DNS lookups."
        )

    def _execute_dig(self, domain: str, dns_server: str, record_type: str = "A") -> str:
        """Run dig subprocess and return raw output.

        Executes ``dig +short <domain> @<dns_server>`` for the given record type
        with a 10-second timeout.

        Args:
            domain: Domain name to resolve.
            dns_server: DNS server IP address.
            record_type: DNS record type ('A' or 'AAAA').

        Returns:
            Raw stdout string from dig.

        Raises:
            subprocess.TimeoutExpired: If dig exceeds DIG_TIMEOUT seconds.
            subprocess.CalledProcessError: If dig returns non-zero exit code.
        """
        cmd = [self._dig_path(), "+short", record_type, domain, f"@{dns_server}"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.DIG_TIMEOUT,
            check=True,
        )
        return result.stdout

    def _parse_dig_output(self, output: str) -> set[str]:
        """Extract valid IPv4/IPv6 addresses from dig +short output.

        Discards CNAME lines, empty lines, and any non-IP content.

        Args:
            output: Raw output string from dig +short.

        Returns:
            Set of valid IP address strings.
        """
        ips = set()
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                addr = ipaddress.ip_address(line)
                ips.add(str(addr))
            except ValueError:
                # Not a valid IP — skip CNAME lines, trailing dots, etc.
                continue
        return ips

    def _compute_diff(self, entry_id: int, new_ips: set[str]) -> tuple[set[str], set[str]]:
        """Compare new IPs against stored dns_resolved_ips.

        Args:
            entry_id: The DNS block entry ID.
            new_ips: Set of IPs from the latest dig lookup.

        Returns:
            Tuple of (ips_to_add, ips_to_remove) where:
            - ips_to_add = new_ips - old_ips
            - ips_to_remove = old_ips - new_ips
        """
        old_ips = set(self._get_resolved_ips(entry_id))
        ips_to_add = new_ips - old_ips
        ips_to_remove = old_ips - new_ips
        return ips_to_add, ips_to_remove

    def refresh_entry(self, entry_id: int, trigger: str = "manual") -> dict:
        """Execute a full refresh cycle: lookup, diff, sync, audit.

        1. Load entry from DB
        2. Execute dig for A and AAAA records
        3. On failure: increment consecutive_failures, set status to 'error'
           at threshold, retain previous IPs, write audit log
        4. On success: reset failures, compute diff, add new IPs via
           RulesEngine, handle stale IP cleanup, update timestamps, audit

        Args:
            entry_id: The database ID of the entry to refresh.
            trigger: The trigger type ('manual', 'scheduled', or 'initial').

        Returns:
            Dict with refresh result summary.

        Raises:
            ValueError: If the entry is not found.
        """
        # Load entry
        with get_db(self.db_path) as conn:
            entry = conn.execute(
                "SELECT * FROM dns_block_entries WHERE id = ?", (entry_id,)
            ).fetchone()
            if not entry:
                raise ValueError(f"DNS block entry with id {entry_id} not found")

        domain = entry["domain"]
        dns_server = entry["dns_server"]
        stale_cleanup = bool(entry["stale_cleanup"])
        consecutive_failures = entry["consecutive_failures"] or 0

        logger.info(
            "Refresh started for DNS entry '%s' (server=%s, trigger=%s)",
            domain, dns_server, trigger,
        )

        start_time = time.time()
        previous_ips = set(self._get_resolved_ips(entry_id))

        # --- Execute dig lookups ---
        lookup_failed = False
        error_msg = None
        all_ips = set()

        try:
            a_output = self._execute_dig(domain, dns_server, "A")
            all_ips |= self._parse_dig_output(a_output)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError) as e:
            lookup_failed = True
            error_msg = f"A record lookup failed: {e}"
            logger.warning("dig A failed for '%s': %s", domain, e)

        try:
            aaaa_output = self._execute_dig(domain, dns_server, "AAAA")
            all_ips |= self._parse_dig_output(aaaa_output)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError) as e:
            if not lookup_failed:
                # Only treat as failure if A also failed or returned nothing
                # If A succeeded with IPs, AAAA failure alone is not a full failure
                logger.warning("dig AAAA failed for '%s': %s", domain, e)
            else:
                error_msg += f"; AAAA record lookup failed: {e}"

        # If both lookups failed, it's a failure
        if lookup_failed and not all_ips:
            pass  # handled below

        # Treat zero valid IPs when entry had previous IPs as lookup failure
        if not all_ips and previous_ips:
            lookup_failed = True
            if not error_msg:
                error_msg = "Lookup returned zero valid IPs (previous IPs existed)"

        # --- Handle failure ---
        if lookup_failed and not all_ips:
            duration = time.time() - start_time
            consecutive_failures += 1
            new_status = "error" if consecutive_failures >= self.CONSECUTIVE_FAILURE_THRESHOLD else "failed"

            with get_db(self.db_path) as conn:
                conn.execute(
                    """UPDATE dns_block_entries
                       SET last_refresh_time = CURRENT_TIMESTAMP,
                           last_refresh_status = ?,
                           last_refresh_duration = ?,
                           consecutive_failures = ?,
                           updated_at = CURRENT_TIMESTAMP
                       WHERE id = ?""",
                    (new_status, duration, consecutive_failures, entry_id),
                )

            _write_audit_log(
                self.db_path,
                event_type="dns_refresh",
                action=f"DNS refresh failed for '{domain}' ({trigger})",
                details={
                    "entry_id": entry_id,
                    "domain": domain,
                    "trigger": trigger,
                    "error": error_msg,
                    "consecutive_failures": consecutive_failures,
                    "ips_retained": len(previous_ips),
                    "duration": round(duration, 2),
                },
            )

            logger.error(
                "Refresh failed for DNS entry '%s': %s (failures=%d)",
                domain, error_msg, consecutive_failures,
            )

            return {
                "entry_id": entry_id,
                "domain": domain,
                "status": new_status,
                "trigger": trigger,
                "error": error_msg,
                "consecutive_failures": consecutive_failures,
                "ips_added": 0,
                "ips_removed": 0,
                "duration": round(duration, 2),
            }

        # --- Handle success ---
        ips_to_add, ips_to_remove = self._compute_diff(entry_id, all_ips)

        # Add new IPs via RulesEngine
        added_by = f"dns:{domain}"
        ips_added_count = 0
        if ips_to_add:
            try:
                result = self.rules_engine.process_block(
                    list(ips_to_add), added_by, skip_invalid=True,
                )
                ips_added_count = len(result.get("ips_added", []))
            except Exception as e:
                logger.error(
                    "Error adding new IPs for DNS entry '%s': %s", domain, e,
                )

        # Handle stale IPs
        ips_removed_count = 0
        if ips_to_remove and stale_cleanup:
            for stale_ip in ips_to_remove:
                if self._is_ip_exclusive(stale_ip, entry_id):
                    try:
                        self.rules_engine.process_unblock([stale_ip], added_by)
                        ips_removed_count += 1
                    except Exception as e:
                        logger.error(
                            "Error removing stale IP %s for DNS entry '%s': %s",
                            stale_ip, domain, e,
                        )

        # Update dns_resolved_ips table
        with get_db(self.db_path) as conn:
            # Insert new IPs
            for ip in ips_to_add:
                conn.execute(
                    """INSERT OR IGNORE INTO dns_resolved_ips
                       (dns_block_entry_id, ip_address)
                       VALUES (?, ?)""",
                    (entry_id, ip),
                )

            # Delete stale IPs (if cleanup enabled)
            if stale_cleanup:
                for ip in ips_to_remove:
                    conn.execute(
                        """DELETE FROM dns_resolved_ips
                           WHERE dns_block_entry_id = ? AND ip_address = ?""",
                        (entry_id, ip),
                    )

            # Update last_seen for all current IPs
            for ip in all_ips:
                conn.execute(
                    """UPDATE dns_resolved_ips
                       SET last_seen = CURRENT_TIMESTAMP
                       WHERE dns_block_entry_id = ? AND ip_address = ?""",
                    (entry_id, ip),
                )

        # Count current resolved IPs
        current_ip_count = len(all_ips) if stale_cleanup else len(previous_ips | ips_to_add)

        duration = time.time() - start_time

        # Update entry status
        with get_db(self.db_path) as conn:
            conn.execute(
                """UPDATE dns_block_entries
                   SET last_refresh_time = CURRENT_TIMESTAMP,
                       last_refresh_status = 'success',
                       last_refresh_ip_count = ?,
                       last_refresh_duration = ?,
                       consecutive_failures = 0,
                       updated_at = CURRENT_TIMESTAMP
                   WHERE id = ?""",
                (current_ip_count, duration, entry_id),
            )

        # Write audit log
        _write_audit_log(
            self.db_path,
            event_type="dns_refresh",
            action=f"DNS refresh completed for '{domain}' ({trigger})",
            details={
                "entry_id": entry_id,
                "domain": domain,
                "trigger": trigger,
                "ips_added": ips_added_count,
                "ips_removed": ips_removed_count,
                "total_ips": current_ip_count,
                "duration": round(duration, 2),
            },
        )

        logger.info(
            "Refresh completed for DNS entry '%s': +%d -%d IPs in %.2fs",
            domain, ips_added_count, ips_removed_count, duration,
        )

        return {
            "entry_id": entry_id,
            "domain": domain,
            "status": "success",
            "trigger": trigger,
            "ips_added": ips_added_count,
            "ips_removed": ips_removed_count,
            "total_ips": current_ip_count,
            "duration": round(duration, 2),
        }

