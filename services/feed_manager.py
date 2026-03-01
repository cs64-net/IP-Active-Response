"""Feed manager for external blocklist feed subscriptions.

Orchestrates feed CRUD, validation, and refresh cycles. Coordinates
with FeedParser for fetching/parsing and DiffSyncEngine for
differential synchronization.
"""

from __future__ import annotations

import logging
import string
import time
from urllib.parse import urlparse

from database import get_db
from services.blocklist_service import BlocklistService
from services.diff_sync_engine import DiffSyncEngine
from services.feed_parser import FeedParser
from services.feed_types import FeedFetchError
from services.rules_engine import RulesEngine, _write_audit_log

logger = logging.getLogger(__name__)


class FeedManager:
    """Orchestrates feed CRUD, validation, and refresh cycles."""

    def __init__(self, db_path: str = None, scheduler=None):
        """Initialize with database path.

        Args:
            db_path: Path to the SQLite database file. Defaults to Config.DATABASE_PATH.
            scheduler: Optional FeedScheduler instance for cancelling jobs on deletion.
        """
        self.db_path = db_path
        self.scheduler = scheduler
        self.blocklist_service = BlocklistService(db_path=db_path)
        self.feed_parser = FeedParser(self.blocklist_service)
        self.rules_engine = RulesEngine(db_path=db_path)
        self.diff_sync_engine = DiffSyncEngine(db_path=db_path, rules_engine=self.rules_engine)
    @staticmethod
    def _validate_url(url: str) -> None:
        """Validate a feed URL has an acceptable scheme, hostname, and path.

        Args:
            url: The URL string to validate.

        Raises:
            ValueError: If the URL fails any validation check.
        """
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Feed URL must use http or https scheme, got '{parsed.scheme}'")
        if not parsed.hostname:
            raise ValueError("Feed URL must contain a valid hostname")
        if not parsed.path or parsed.path == "/":
            raise ValueError("Feed URL must contain a non-empty path (not just '/')")
    @staticmethod
    def _validate_name(name: str) -> None:
        """Validate a feed name for length and character constraints.

        Args:
            name: The feed name to validate.

        Raises:
            ValueError: If the name is empty, too long, or contains control characters.
        """
        if not name or len(name) > 100:
            raise ValueError(
                "Feed name must be between 1 and 100 characters"
            )
        # Allow only printable ASCII (space 0x20 through tilde 0x7E)
        for ch in name:
            if ord(ch) < 32 or ord(ch) > 126:
                raise ValueError(
                    "Feed name must contain only printable characters (no control characters)"
                )


    def create_feed(self, name: str, url: str, refresh_interval: int, enabled: bool = True) -> dict:
        """Validate URL, test fetch, create feed record.

        - Validates URL scheme (http/https only)
        - Enforces unique name and URL
        - Validates refresh_interval in [60, 86400]
        - Performs test fetch and parse
        - Returns feed dict with ip_count from test fetch
        - Raises ValueError on validation failure

        Args:
            name: Human-readable feed name.
            url: HTTP/HTTPS URL of the blocklist feed.
            refresh_interval: Refresh interval in seconds (60-86400).
            enabled: Whether the feed is enabled on creation.

        Returns:
            Dict representing the created feed record with ip_count.
        """
        # Validate URL
        self._validate_url(url)

        # Validate name
        self._validate_name(name)

        # Validate refresh interval
        if not isinstance(refresh_interval, int) or refresh_interval < 60 or refresh_interval > 86400:
            raise ValueError(
                f"Refresh interval must be an integer between 60 and 86400 seconds, got {refresh_interval}"
            )

        # Enforce unique name and URL
        with get_db(self.db_path) as conn:
            existing_name = conn.execute(
                "SELECT id FROM feeds WHERE name = ?", (name,)
            ).fetchone()
            if existing_name:
                raise ValueError(f"A feed with name '{name}' already exists")

            existing_url = conn.execute(
                "SELECT id FROM feeds WHERE url = ?", (url,)
            ).fetchone()
            if existing_url:
                raise ValueError(f"A feed with URL '{url}' already exists")

        # Test fetch and parse
        try:
            parse_result = self.feed_parser.fetch_and_parse(url)
        except FeedFetchError as e:
            raise ValueError(f"Test fetch failed: {e}") from e

        if parse_result.valid_count == 0:
            raise ValueError("Test fetch returned zero valid IPs")

        # Create the feed record
        with get_db(self.db_path) as conn:
            cursor = conn.execute(
                """INSERT INTO feeds (name, url, refresh_interval, enabled)
                   VALUES (?, ?, ?, ?)""",
                (name, url, refresh_interval, 1 if enabled else 0),
            )
            feed_id = cursor.lastrowid

        # Write audit log
        _write_audit_log(
            self.db_path,
            event_type="feed_management",
            action=f"Feed '{name}' created",
            details={
                "feed_id": feed_id,
                "name": name,
                "url": url,
                "refresh_interval": refresh_interval,
                "enabled": enabled,
                "test_ip_count": parse_result.valid_count,
            },
        )

        logger.info("Created feed '%s' (id=%d, url=%s, interval=%ds, ips=%d)",
                     name, feed_id, url, refresh_interval, parse_result.valid_count)

        return self._feed_to_dict(feed_id, ip_count=parse_result.valid_count)

    def update_feed(self, feed_id: int, **kwargs) -> dict:
        """Update feed fields (name, url, refresh_interval, enabled).

        Args:
            feed_id: The database ID of the feed to update.
            **kwargs: Fields to update. Supported: name, url, refresh_interval, enabled.

        Returns:
            Dict representing the updated feed record.

        Raises:
            ValueError: If the feed is not found or validation fails.
        """
        allowed_fields = {"name", "url", "refresh_interval", "enabled"}
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if not updates:
            raise ValueError("No valid fields to update")

        # Validate fields if provided
        if "url" in updates:
            self._validate_url(updates["url"])

        if "name" in updates:
            self._validate_name(updates["name"])

        if "refresh_interval" in updates:
            interval = updates["refresh_interval"]
            if not isinstance(interval, int) or interval < 60 or interval > 86400:
                raise ValueError(
                    f"Refresh interval must be an integer between 60 and 86400 seconds, got {interval}"
                )

        with get_db(self.db_path) as conn:
            # Check feed exists
            existing = conn.execute("SELECT * FROM feeds WHERE id = ?", (feed_id,)).fetchone()
            if not existing:
                raise ValueError(f"Feed with id {feed_id} not found")

            # Enforce unique name/url if changing
            if "name" in updates and updates["name"] != existing["name"]:
                dup = conn.execute(
                    "SELECT id FROM feeds WHERE name = ? AND id != ?",
                    (updates["name"], feed_id),
                ).fetchone()
                if dup:
                    raise ValueError(f"A feed with name '{updates['name']}' already exists")

            if "url" in updates and updates["url"] != existing["url"]:
                dup = conn.execute(
                    "SELECT id FROM feeds WHERE url = ? AND id != ?",
                    (updates["url"], feed_id),
                ).fetchone()
                if dup:
                    raise ValueError(f"A feed with URL '{updates['url']}' already exists")

            # Convert enabled bool to int for SQLite
            if "enabled" in updates:
                updates["enabled"] = 1 if updates["enabled"] else 0

            # Build and execute UPDATE
            set_clause = ", ".join(f"{k} = ?" for k in updates)
            set_clause += ", updated_at = CURRENT_TIMESTAMP"
            values = list(updates.values()) + [feed_id]
            conn.execute(
                f"UPDATE feeds SET {set_clause} WHERE id = ?",
                values,
            )

        _write_audit_log(
            self.db_path,
            event_type="feed_management",
            action=f"Feed id={feed_id} updated",
            details={"feed_id": feed_id, "updates": {k: v for k, v in kwargs.items() if k in allowed_fields}},
        )

        logger.info("Updated feed id=%d: %s", feed_id, updates)
        return self._feed_to_dict(feed_id)

    def delete_feed(self, feed_id: int) -> None:
        """Delete feed, remove exclusive IPs, clean up feed_entries.

        Removes the feed record, all associated feed_entry records, and
        enqueues bulk remove operations for IPs exclusive to this feed.

        Args:
            feed_id: The database ID of the feed to delete.

        Raises:
            ValueError: If the feed is not found.
        """
        with get_db(self.db_path) as conn:
            feed = conn.execute("SELECT * FROM feeds WHERE id = ?", (feed_id,)).fetchone()
            if not feed:
                raise ValueError(f"Feed with id {feed_id} not found")
            feed_name = feed["name"]

        # Cancel any scheduled refresh job before cleanup (Requirements 3.2)
        if self.scheduler is not None:
            try:
                self.scheduler.cancel_feed(feed_id)
            except Exception as e:
                logger.warning("Failed to cancel scheduled job for feed %d: %s", feed_id, e)

        # Get current IPs for this feed and find exclusive ones
        previous_ips = self.diff_sync_engine._get_previous_ips(feed_id)
        exclusive_ips = [
            ip for ip in previous_ips
            if self.diff_sync_engine._is_ip_exclusive_to_feed(ip, feed_id)
        ]

        # Bulk remove exclusive IPs via RulesEngine if available
        removal_errors = 0
        if exclusive_ips and self.diff_sync_engine.rules_engine:
            added_by = f"feed:{feed_name}"
            sorted_ips = sorted(exclusive_ips)
            for i in range(0, len(sorted_ips), DiffSyncEngine.CHUNK_SIZE):
                chunk = sorted_ips[i : i + DiffSyncEngine.CHUNK_SIZE]
                try:
                    self.diff_sync_engine.rules_engine.process_unblock(chunk, added_by)
                except Exception as e:
                    removal_errors += 1
                    logger.error("Error removing chunk of %d IPs for deleted feed '%s': %s", len(chunk), feed_name, e)

        # Remove feed_entries and feed record regardless of unblock failures
        with get_db(self.db_path) as conn:
            conn.execute("DELETE FROM feed_entries WHERE feed_id = ?", (feed_id,))
            conn.execute("DELETE FROM feeds WHERE id = ?", (feed_id,))

        _write_audit_log(
            self.db_path,
            event_type="feed_management",
            action=f"Feed '{feed_name}' deleted",
            details={
                "feed_id": feed_id,
                "name": feed_name,
                "exclusive_ips_removed": len(exclusive_ips),
                "removal_errors": removal_errors,
            },
        )

        logger.info("Deleted feed '%s' (id=%d), removed %d exclusive IPs, %d removal errors",
                     feed_name, feed_id, len(exclusive_ips), removal_errors)

    def get_feed(self, feed_id: int) -> dict:
        """Get a single feed by ID.

        Args:
            feed_id: The database ID of the feed.

        Returns:
            Dict representing the feed record.

        Raises:
            ValueError: If the feed is not found.
        """
        with get_db(self.db_path) as conn:
            row = conn.execute("SELECT * FROM feeds WHERE id = ?", (feed_id,)).fetchone()
            if not row:
                raise ValueError(f"Feed with id {feed_id} not found")
            return dict(row)

    def get_all_feeds(self) -> list[dict]:
        """Get all configured feeds with state.

        Returns:
            List of dicts representing all feed records.
        """
        with get_db(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM feeds ORDER BY created_at DESC"
            ).fetchall()
            return [dict(row) for row in rows]

    def toggle_feed(self, feed_id: int, enabled: bool) -> None:
        """Enable or disable a feed.

        Args:
            feed_id: The database ID of the feed.
            enabled: True to enable, False to disable.

        Raises:
            ValueError: If the feed is not found.
        """
        with get_db(self.db_path) as conn:
            existing = conn.execute("SELECT id FROM feeds WHERE id = ?", (feed_id,)).fetchone()
            if not existing:
                raise ValueError(f"Feed with id {feed_id} not found")

            conn.execute(
                "UPDATE feeds SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (1 if enabled else 0, feed_id),
            )

        state_str = "enabled" if enabled else "disabled"
        _write_audit_log(
            self.db_path,
            event_type="feed_management",
            action=f"Feed id={feed_id} {state_str}",
            details={"feed_id": feed_id, "enabled": enabled},
        )

        logger.info("Feed id=%d %s", feed_id, state_str)

    def refresh_feed(self, feed_id: int, trigger: str = "manual") -> dict:
        """Execute a full refresh cycle for a feed.

        1. Log refresh start
        2. Fetch and parse via FeedParser
        3. Compute diff via DiffSyncEngine
        4. Apply diff via DiffSyncEngine
        5. Update feed state (last_fetch_time, status, ip_count, duration)
        6. Log refresh completion
        7. Return refresh result summary

        On failure: log error, update feed status to 'failed', retain previous IPs.

        Args:
            feed_id: The database ID of the feed to refresh.
            trigger: The trigger type ('manual' or 'scheduled').

        Returns:
            Dict with refresh result summary including ips_parsed, ips_added,
            ips_removed, duration, and status.

        Raises:
            ValueError: If the feed is not found.
        """
        # Load feed record
        with get_db(self.db_path) as conn:
            feed = conn.execute("SELECT * FROM feeds WHERE id = ?", (feed_id,)).fetchone()
            if not feed:
                raise ValueError(f"Feed with id {feed_id} not found")
            feed_name = feed["name"]
            feed_url = feed["url"]

        # Log refresh start
        logger.info(
            "Refresh started for feed '%s' (url=%s, trigger=%s)",
            feed_name, feed_url, trigger,
        )

        start_time = time.time()

        try:
            # Fetch and parse
            parse_result = self.feed_parser.fetch_and_parse(feed_url)

            # Treat zero valid IPs as a failure (Requirement 2.7)
            if parse_result.valid_count == 0:
                raise FeedFetchError("Feed returned zero valid IPs after parsing")

            # Check for malformed feed (Requirement 2.4)
            total_data_lines = parse_result.valid_count + parse_result.invalid_count
            if total_data_lines > 0 and parse_result.invalid_count / total_data_lines > 0.5:
                logger.warning(
                    "Feed '%s' may be malformed: %d of %d data lines were invalid (%.0f%%)",
                    feed_name,
                    parse_result.invalid_count,
                    total_data_lines,
                    (parse_result.invalid_count / total_data_lines) * 100,
                )

            # IP count warning (Requirements 1.1, 1.2, 1.3, 1.5)
            ip_count_warning = parse_result.valid_count > 500
            ip_count_warning_message = None
            if ip_count_warning:
                ip_count_warning_message = (
                    f"Warning: Feed '{feed_name}' contains {parse_result.valid_count} IPs. "
                    f"Some platforms have limits on the number of IPs in an alias or "
                    f"object-group and proceeding may cause instability."
                )
                logger.warning(
                    "Feed '%s' contains %d IPs, exceeding the 500 IP threshold",
                    feed_name,
                    parse_result.valid_count,
                )
                _write_audit_log(
                    self.db_path,
                    event_type="feed_ip_count_warning",
                    action=f"Feed '{feed_name}' contains {parse_result.valid_count} IPs (exceeds 500 threshold)",
                    details={
                        "feed_id": feed_id,
                        "feed_name": feed_name,
                        "ip_count": parse_result.valid_count,
                    },
                )

            # Compute diff
            diff = self.diff_sync_engine.compute_diff(feed_id, parse_result.ip_set)

            # Apply diff
            sync_result = self.diff_sync_engine.apply_diff(feed_id, feed_name, diff)

            duration = time.time() - start_time

            # Update feed state on success
            with get_db(self.db_path) as conn:
                conn.execute(
                    """UPDATE feeds
                       SET last_fetch_time = CURRENT_TIMESTAMP,
                           last_fetch_status = 'success',
                           last_fetch_ip_count = ?,
                           last_fetch_duration = ?,
                           updated_at = CURRENT_TIMESTAMP
                       WHERE id = ?""",
                    (parse_result.valid_count, duration, feed_id),
                )

            # Log refresh completion
            logger.info(
                "Refresh completed for feed '%s': %d IPs parsed, %d added, %d removed in %.2fs",
                feed_name,
                parse_result.valid_count,
                sync_result.ips_added,
                sync_result.ips_removed,
                duration,
            )

            # Write audit log for successful refresh
            _write_audit_log(
                self.db_path,
                event_type="feed_refresh",
                action=f"Feed '{feed_name}' refreshed ({trigger})",
                details={
                    "feed_id": feed_id,
                    "feed_name": feed_name,
                    "trigger": trigger,
                    "ips_parsed": parse_result.valid_count,
                    "invalid_count": parse_result.invalid_count,
                    "ips_added": sync_result.ips_added,
                    "ips_removed": sync_result.ips_removed,
                    "duration": round(duration, 2),
                },
            )

            return {
                "feed_id": feed_id,
                "feed_name": feed_name,
                "status": "success",
                "trigger": trigger,
                "ips_parsed": parse_result.valid_count,
                "invalid_count": parse_result.invalid_count,
                "ips_added": sync_result.ips_added,
                "ips_removed": sync_result.ips_removed,
                "duration": round(duration, 2),
                "errors": sync_result.errors,
                "ip_count_warning": ip_count_warning,
                "ip_count_warning_message": ip_count_warning_message,
            }

        except Exception as e:
            duration = time.time() - start_time

            # Determine HTTP status code if available
            status_code = getattr(e, "status_code", None)

            # Log error
            logger.error(
                "Refresh failed for feed '%s': %s (status_code=%s)",
                feed_name, e, status_code,
            )

            # Update feed status to 'failed', retain previous IPs
            with get_db(self.db_path) as conn:
                conn.execute(
                    """UPDATE feeds
                       SET last_fetch_status = 'failed',
                           last_fetch_duration = ?,
                           updated_at = CURRENT_TIMESTAMP
                       WHERE id = ?""",
                    (duration, feed_id),
                )

            # Write audit log for failed refresh
            _write_audit_log(
                self.db_path,
                event_type="feed_refresh",
                action=f"Feed '{feed_name}' refresh failed ({trigger})",
                details={
                    "feed_id": feed_id,
                    "feed_name": feed_name,
                    "trigger": trigger,
                    "error": str(e),
                    "status_code": status_code,
                    "duration": round(duration, 2),
                },
            )

            return {
                "feed_id": feed_id,
                "feed_name": feed_name,
                "status": "failed",
                "trigger": trigger,
                "error": str(e),
                "duration": round(duration, 2),
            }


    def _feed_to_dict(self, feed_id: int, ip_count: int | None = None) -> dict:
        """Helper to load a feed record as a dict, optionally overriding ip_count.

        Args:
            feed_id: The database ID of the feed.
            ip_count: If provided, override the last_fetch_ip_count value.

        Returns:
            Dict representing the feed record.
        """
        with get_db(self.db_path) as conn:
            row = conn.execute("SELECT * FROM feeds WHERE id = ?", (feed_id,)).fetchone()
            if not row:
                raise ValueError(f"Feed with id {feed_id} not found")
            result = dict(row)
            if ip_count is not None:
                result["ip_count"] = ip_count
            return result
