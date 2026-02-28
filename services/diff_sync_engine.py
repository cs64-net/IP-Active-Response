"""Differential synchronization engine for external blocklist feeds.

Computes differential changes between feed refreshes and manages
feed_entries records for multi-feed overlap detection.
"""

from __future__ import annotations

import logging
import time

from database import get_db
from services.feed_types import DiffResult, SyncResult

logger = logging.getLogger(__name__)


class DiffSyncEngine:
    """Computes differential changes and applies them via the RulesEngine."""

    CHUNK_SIZE = 1000

    def __init__(self, db_path: str = None, rules_engine=None):
        """Initialize with database path and optional RulesEngine.

        Args:
            db_path: Path to the SQLite database file. Defaults to Config.DATABASE_PATH.
            rules_engine: RulesEngine instance for bulk block/unblock operations.
        """
        self.db_path = db_path
        self.rules_engine = rules_engine

    def compute_diff(self, feed_id: int, new_ips: set[str]) -> DiffResult:
        """Compute IPs to add and IPs to remove for a feed.

        Compares the new IP set against the previously stored set for this feed
        and returns the set differences.

        Args:
            feed_id: The database ID of the feed.
            new_ips: The current set of IPs parsed from the feed.

        Returns:
            DiffResult with ips_to_add (new - previous) and ips_to_remove (previous - new).
        """
        previous_ips = self._get_previous_ips(feed_id)
        ips_to_add = new_ips - previous_ips
        ips_to_remove = previous_ips - new_ips
        return DiffResult(ips_to_add=ips_to_add, ips_to_remove=ips_to_remove)

    def apply_diff(self, feed_id: int, feed_name: str, diff: DiffResult) -> SyncResult:
        """Apply computed diff: bulk add new IPs, bulk remove stale IPs.

        Adds new IPs via RulesEngine.process_block() in chunks of CHUNK_SIZE.
        Only removes IPs not present in other active feeds or manually added.
        Removes via RulesEngine.process_unblock() in chunks.
        Updates feed_entries table to reflect current IP set.

        Args:
            feed_id: The database ID of the feed.
            feed_name: The name of the feed (used for added_by tagging).
            diff: DiffResult containing ips_to_add and ips_to_remove sets.

        Returns:
            SyncResult with counts, operation_ids, and any errors.
        """
        start_time = time.time()
        operation_ids: list[str] = []
        errors: list[str] = []
        total_added = 0
        total_removed = 0

        added_by = f"feed:{feed_name}"

        # Process additions in chunks
        ips_to_add_list = sorted(diff.ips_to_add)
        for i in range(0, len(ips_to_add_list), self.CHUNK_SIZE):
            chunk = ips_to_add_list[i : i + self.CHUNK_SIZE]
            try:
                result = self.rules_engine.process_block(chunk, added_by, skip_invalid=True)
                operation_ids.append(result["operation_id"])
                total_added += len(result.get("ips_added", []))
                if result.get("errors"):
                    errors.extend(result["errors"])
            except Exception as e:
                logger.error("Error adding chunk %d for feed %s: %s", i // self.CHUNK_SIZE, feed_name, e)
                errors.append(f"Add chunk {i // self.CHUNK_SIZE} failed: {e}")

        # Filter removals to only exclusive IPs
        exclusive_ips = [
            ip for ip in diff.ips_to_remove
            if self._is_ip_exclusive_to_feed(ip, feed_id)
        ]

        # Process removals in chunks
        exclusive_ips_sorted = sorted(exclusive_ips)
        for i in range(0, len(exclusive_ips_sorted), self.CHUNK_SIZE):
            chunk = exclusive_ips_sorted[i : i + self.CHUNK_SIZE]
            try:
                result = self.rules_engine.process_unblock(chunk, added_by)
                operation_ids.append(result["operation_id"])
                total_removed += len(result.get("ips_removed", []))
                if result.get("errors"):
                    errors.extend(result["errors"])
            except Exception as e:
                logger.error("Error removing chunk %d for feed %s: %s", i // self.CHUNK_SIZE, feed_name, e)
                errors.append(f"Remove chunk {i // self.CHUNK_SIZE} failed: {e}")

        # Compute the new full IP set and update feed_entries
        previous_ips = self._get_previous_ips(feed_id)
        current_ips = (previous_ips | diff.ips_to_add) - diff.ips_to_remove
        self._update_feed_entries(feed_id, current_ips)

        duration = time.time() - start_time
        logger.info(
            "Feed %s sync complete: %d added, %d removed in %.2fs",
            feed_name, total_added, total_removed, duration,
        )

        return SyncResult(
            ips_added=total_added,
            ips_removed=total_removed,
            duration_seconds=duration,
            operation_ids=operation_ids,
            errors=errors,
        )


    def _get_previous_ips(self, feed_id: int) -> set[str]:
        """Load the previous IP set for a feed from feed_entries table.

        Args:
            feed_id: The database ID of the feed.

        Returns:
            Set of IP address strings previously associated with this feed.
        """
        with get_db(self.db_path) as conn:
            rows = conn.execute(
                "SELECT ip_address FROM feed_entries WHERE feed_id = ?",
                (feed_id,),
            ).fetchall()
            return {row["ip_address"] for row in rows}

    def _is_ip_exclusive_to_feed(self, ip: str, feed_id: int) -> bool:
        """Check if an IP is only in this feed and not manually added.

        An IP is exclusive to a feed if:
        1. No other feed_entries rows exist for that IP with a different feed_id
        2. The IP is not in block_entries with added_by NOT starting with 'feed:'
           (i.e., not manually added)

        Args:
            ip: The IP address to check.
            feed_id: The feed ID to check exclusivity against.

        Returns:
            True if the IP is exclusive to this feed, False otherwise.
        """
        with get_db(self.db_path) as conn:
            # Check if any other feed has this IP
            other_feed = conn.execute(
                "SELECT 1 FROM feed_entries WHERE ip_address = ? AND feed_id != ? LIMIT 1",
                (ip, feed_id),
            ).fetchone()
            if other_feed:
                return False

            # Check if the IP was manually added (added_by not starting with 'feed:')
            manual_entry = conn.execute(
                "SELECT 1 FROM block_entries WHERE ip_address = ? AND added_by NOT LIKE 'feed:%' LIMIT 1",
                (ip,),
            ).fetchone()
            if manual_entry:
                return False

            return True

    def _update_feed_entries(self, feed_id: int, current_ips: set[str]) -> None:
        """Replace feed_entries for this feed with the current IP set.

        Deletes all existing feed_entries for the feed and inserts the new set.

        Args:
            feed_id: The database ID of the feed.
            current_ips: The current set of IPs to store for this feed.
        """
        with get_db(self.db_path) as conn:
            conn.execute(
                "DELETE FROM feed_entries WHERE feed_id = ?",
                (feed_id,),
            )
            for ip in current_ips:
                conn.execute(
                    "INSERT INTO feed_entries (feed_id, ip_address) VALUES (?, ?)",
                    (feed_id, ip),
                )
