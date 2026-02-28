"""Feed routes for managing external blocklist feed subscriptions."""

import logging
from typing import Optional

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for

from auth import login_required
from config import Config
from services.feed_manager import FeedManager
from services.feed_scheduler import FeedScheduler

logger = logging.getLogger(__name__)

feed_bp = Blueprint("feeds", __name__)

# Module-level references set during app initialization (task 9.1)
_feed_scheduler: Optional[FeedScheduler] = None


def init_feed_routes(feed_scheduler: FeedScheduler):
    """Initialize module-level scheduler reference for use by routes."""
    global _feed_scheduler
    _feed_scheduler = feed_scheduler


def _get_feed_manager() -> FeedManager:
    """Create a FeedManager using the configured database path."""
    return FeedManager(db_path=Config.DATABASE_PATH)


def _get_feed_scheduler() -> Optional[FeedScheduler]:
    """Return the module-level FeedScheduler instance."""
    return _feed_scheduler


@feed_bp.route("/feeds")
@login_required
def index():
    """Render External Blocklists Tab page."""
    manager = _get_feed_manager()
    try:
        all_feeds = manager.get_all_feeds()
    except Exception as e:
        logger.error("Error fetching feeds: %s", e)
        all_feeds = []
    # Exclude geo-blocking feeds (identified by "Geo: " name prefix) from the manual feed list
    feeds = [f for f in all_feeds if not f.get("name", "").startswith("Geo: ")]
    return render_template("feeds.html", feeds=feeds, existing_feed_urls={f.get("url", ""): f.get("id") for f in feeds})


@feed_bp.route("/feeds/add", methods=["POST"])
@login_required
def add_feed():
    """Create a new feed: validate, test fetch, create, schedule."""
    name = request.form.get("name", "").strip()
    url = request.form.get("url", "").strip()
    interval_str = request.form.get("refresh_interval", "").strip()
    enabled = request.form.get("enabled") == "on"

    if not name or not url:
        flash("Name and URL are required.", "error")
        return redirect(url_for("feeds.index"))

    try:
        refresh_interval = int(interval_str)
    except (ValueError, TypeError):
        flash("Refresh interval must be a valid integer.", "error")
        return redirect(url_for("feeds.index"))

    manager = _get_feed_manager()
    try:
        feed = manager.create_feed(name, url, refresh_interval, enabled)
        # Immediately sync the feed IPs to blocklist and devices
        try:
            refresh_result = manager.refresh_feed(feed["id"], trigger="initial")
            ip_count = refresh_result.get("ips_added", 0)
        except Exception as refresh_err:
            logger.warning("Initial refresh for feed '%s' failed: %s", name, refresh_err)
            ip_count = feed.get('last_fetch_ip_count', 0)
        # Schedule if enabled
        scheduler = _get_feed_scheduler()
        if scheduler and enabled:
            scheduler.schedule_feed(feed["id"], refresh_interval)
        flash(f"Feed '{name}' created with {ip_count} IPs synced.")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        logger.error("Unexpected error creating feed '%s': %s", name, e)
        flash("An unexpected error occurred while creating the feed.", "error")

    return redirect(url_for("feeds.index"))


@feed_bp.route("/feeds/<int:feed_id>/edit", methods=["POST"])
@login_required
def edit_feed(feed_id):
    """Update feed fields, reschedule if interval changed."""
    manager = _get_feed_manager()

    kwargs = {}
    name = request.form.get("name", "").strip()
    url = request.form.get("url", "").strip()
    interval_str = request.form.get("refresh_interval", "").strip()

    if name:
        kwargs["name"] = name
    if url:
        kwargs["url"] = url
    if interval_str:
        try:
            kwargs["refresh_interval"] = int(interval_str)
        except (ValueError, TypeError):
            flash("Refresh interval must be a valid integer.", "error")
            return redirect(url_for("feeds.index"))

    if not kwargs:
        flash("No fields to update.", "error")
        return redirect(url_for("feeds.index"))

    try:
        old_feed = manager.get_feed(feed_id)
        feed = manager.update_feed(feed_id, **kwargs)

        # Reschedule if interval changed
        scheduler = _get_feed_scheduler()
        if scheduler and "refresh_interval" in kwargs:
            old_interval = old_feed.get("refresh_interval")
            new_interval = kwargs["refresh_interval"]
            if old_interval != new_interval:
                if old_feed.get("enabled"):
                    scheduler.reschedule_feed(feed_id, new_interval)

        flash(f"Feed '{feed.get('name', feed_id)}' updated.")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        logger.error("Unexpected error updating feed %d: %s", feed_id, e)
        flash("An unexpected error occurred while updating the feed.", "error")

    return redirect(url_for("feeds.index"))


@feed_bp.route("/feeds/<int:feed_id>/delete", methods=["POST"])
@login_required
def delete_feed(feed_id):
    """Delete feed, cancel schedule, clean up IPs."""
    manager = _get_feed_manager()
    try:
        feed = manager.get_feed(feed_id)
        feed_name = feed["name"]

        # Cancel scheduled job
        scheduler = _get_feed_scheduler()
        if scheduler:
            scheduler.cancel_feed(feed_id)

        manager.delete_feed(feed_id)
        flash(f"Feed '{feed_name}' deleted.")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        logger.error("Unexpected error deleting feed %d: %s", feed_id, e)
        flash("An unexpected error occurred while deleting the feed.", "error")

    return redirect(url_for("feeds.index"))


@feed_bp.route("/feeds/<int:feed_id>/toggle", methods=["POST"])
@login_required
def toggle_feed(feed_id):
    """Enable/disable feed, schedule/cancel accordingly."""
    manager = _get_feed_manager()
    try:
        feed = manager.get_feed(feed_id)
        new_enabled = not bool(feed.get("enabled"))

        manager.toggle_feed(feed_id, new_enabled)

        scheduler = _get_feed_scheduler()
        if scheduler:
            if new_enabled:
                scheduler.schedule_feed(feed_id, feed["refresh_interval"])
            else:
                scheduler.cancel_feed(feed_id)

        state = "enabled" if new_enabled else "disabled"
        flash(f"Feed '{feed['name']}' {state}.")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        logger.error("Unexpected error toggling feed %d: %s", feed_id, e)
        flash("An unexpected error occurred while toggling the feed.", "error")

    return redirect(url_for("feeds.index"))


@feed_bp.route("/feeds/<int:feed_id>/refresh", methods=["POST"])
@login_required
def refresh_feed(feed_id):
    """Trigger manual refresh for a feed."""
    manager = _get_feed_manager()
    try:
        result = manager.refresh_feed(feed_id, trigger="manual")
        status = result.get("status", "unknown")
        if status == "success":
            flash(
                f"Feed refreshed: {result.get('ips_parsed', 0)} IPs parsed, "
                f"{result.get('ips_added', 0)} added, {result.get('ips_removed', 0)} removed."
            )
        else:
            flash(f"Feed refresh failed: {result.get('error', 'unknown error')}", "error")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        logger.error("Unexpected error refreshing feed %d: %s", feed_id, e)
        flash("An unexpected error occurred while refreshing the feed.", "error")

    return redirect(url_for("feeds.index"))


@feed_bp.route("/api/feeds")
@login_required
def api_feeds():
    """JSON list of all feeds with state (excludes geo-blocking feeds)."""
    manager = _get_feed_manager()
    try:
        all_feeds = manager.get_all_feeds()
        # Exclude geo-blocking feeds (identified by "Geo: " name prefix)
        feeds = [f for f in all_feeds if not f.get("name", "").startswith("Geo: ")]
        return jsonify({"success": True, "feeds": feeds})
    except Exception as e:
        logger.error("Error fetching feeds for API: %s", e)
        return jsonify({"success": False, "message": "Failed to fetch feeds."}), 500
