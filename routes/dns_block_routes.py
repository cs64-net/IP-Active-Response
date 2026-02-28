"""DNS block routes for managing domain-based IP blocking entries."""

import logging
from typing import Optional

from flask import Blueprint, flash, redirect, render_template, request, url_for

from auth import login_required
from config import Config
from routes.geo_data import COUNTRIES, POPULAR_COUNTRY_CODES
from routes.geo_routes import get_enabled_countries
from services.dns_block_manager import DNSBlockManager
from services.dns_block_scheduler import DNSBlockScheduler
from services.feed_manager import FeedManager

logger = logging.getLogger(__name__)

dns_block_bp = Blueprint("dns_blocks", __name__)

# Module-level reference set during app initialization
_dns_block_scheduler: Optional[DNSBlockScheduler] = None


def init_dns_block_routes(dns_block_scheduler: DNSBlockScheduler):
    """Initialize module-level scheduler reference for use by routes."""
    global _dns_block_scheduler
    _dns_block_scheduler = dns_block_scheduler


def _get_dns_block_manager() -> DNSBlockManager:
    """Create a DNSBlockManager using the configured database path."""
    return DNSBlockManager(db_path=Config.DATABASE_PATH)


def _get_dns_block_scheduler() -> Optional[DNSBlockScheduler]:
    """Return the module-level DNSBlockScheduler instance."""
    return _dns_block_scheduler


@dns_block_bp.route("/dns-blocks")
@login_required
def index():
    """Render DNS / Geo Blocks page with all entries and geo-blocking context."""
    manager = _get_dns_block_manager()
    try:
        entries = manager.get_all_entries()
    except Exception as e:
        logger.error("Error fetching DNS block entries: %s", e)
        entries = []

    feed_manager = FeedManager(db_path=Config.DATABASE_PATH)
    enabled_countries = get_enabled_countries(feed_manager)

    return render_template("dns_blocks.html",
        entries=entries,
        countries=COUNTRIES,
        popular_codes=POPULAR_COUNTRY_CODES,
        enabled_countries=enabled_countries,
        geo_refresh_interval=86400,
    )


@dns_block_bp.route("/dns-blocks/add", methods=["POST"])
@login_required
def add_entry():
    """Create a new DNS block entry: validate, run initial lookup, schedule."""
    domain = request.form.get("domain", "").strip()
    dns_server = request.form.get("dns_server", "").strip()
    interval_str = request.form.get("refresh_interval", "").strip()
    refresh_unit = request.form.get("refresh_unit", "seconds").strip()
    stale_cleanup = request.form.get("stale_cleanup") == "on"
    enabled = request.form.get("enabled") == "on"

    if not domain or not dns_server:
        flash("Domain and DNS server are required.", "error")
        return redirect(url_for("dns_blocks.index"))

    try:
        refresh_interval = int(interval_str)
    except (ValueError, TypeError):
        flash("Refresh interval must be a valid integer.", "error")
        return redirect(url_for("dns_blocks.index"))

    # Convert minutes to seconds if unit is minutes
    if refresh_unit == "minutes":
        refresh_interval = refresh_interval * 60

    manager = _get_dns_block_manager()
    try:
        entry = manager.create_entry(domain, dns_server, refresh_interval, stale_cleanup, enabled)
        ip_count = entry.get("last_refresh_ip_count", 0)

        # Schedule if enabled
        scheduler = _get_dns_block_scheduler()
        if scheduler and enabled:
            scheduler.schedule_entry(entry["id"], refresh_interval)

        flash(f"DNS block entry '{domain}' created with {ip_count} IPs resolved.")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        logger.error("Unexpected error creating DNS block entry '%s': %s", domain, e)
        flash("An unexpected error occurred while creating the DNS block entry.", "error")

    return redirect(url_for("dns_blocks.index"))


@dns_block_bp.route("/dns-blocks/<int:entry_id>/edit", methods=["POST"])
@login_required
def edit_entry(entry_id):
    """Update DNS block entry fields, reschedule if interval changed."""
    manager = _get_dns_block_manager()

    kwargs = {}
    dns_server = request.form.get("dns_server", "").strip()
    interval_str = request.form.get("refresh_interval", "").strip()
    refresh_unit = request.form.get("refresh_unit", "seconds").strip()
    stale_cleanup = request.form.get("stale_cleanup")
    enabled = request.form.get("enabled")

    if dns_server:
        kwargs["dns_server"] = dns_server
    if interval_str:
        try:
            refresh_interval = int(interval_str)
        except (ValueError, TypeError):
            flash("Refresh interval must be a valid integer.", "error")
            return redirect(url_for("dns_blocks.index"))
        # Convert minutes to seconds if unit is minutes
        if refresh_unit == "minutes":
            refresh_interval = refresh_interval * 60
        kwargs["refresh_interval"] = refresh_interval
    if stale_cleanup is not None:
        kwargs["stale_cleanup"] = stale_cleanup == "on"
    if enabled is not None:
        kwargs["enabled"] = enabled == "on"

    if not kwargs:
        flash("No fields to update.", "error")
        return redirect(url_for("dns_blocks.index"))

    try:
        old_entry = manager.get_entry(entry_id)
        entry = manager.update_entry(entry_id, **kwargs)

        # Reschedule if interval changed
        scheduler = _get_dns_block_scheduler()
        if scheduler and "refresh_interval" in kwargs:
            old_interval = old_entry.get("refresh_interval")
            new_interval = kwargs["refresh_interval"]
            if old_interval != new_interval:
                if old_entry.get("enabled"):
                    scheduler.reschedule_entry(entry_id, new_interval)

        flash(f"DNS block entry '{entry.get('domain', entry_id)}' updated.")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        logger.error("Unexpected error updating DNS block entry %d: %s", entry_id, e)
        flash("An unexpected error occurred while updating the DNS block entry.", "error")

    return redirect(url_for("dns_blocks.index"))


@dns_block_bp.route("/dns-blocks/<int:entry_id>/delete", methods=["POST"])
@login_required
def delete_entry(entry_id):
    """Delete DNS block entry, cancel schedule, clean up IPs."""
    manager = _get_dns_block_manager()
    try:
        entry = manager.get_entry(entry_id)
        domain = entry["domain"]

        # Cancel scheduled job
        scheduler = _get_dns_block_scheduler()
        if scheduler:
            scheduler.cancel_entry(entry_id)

        manager.delete_entry(entry_id)
        flash(f"DNS block entry '{domain}' deleted.")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        logger.error("Unexpected error deleting DNS block entry %d: %s", entry_id, e)
        flash("An unexpected error occurred while deleting the DNS block entry.", "error")

    return redirect(url_for("dns_blocks.index"))


@dns_block_bp.route("/dns-blocks/<int:entry_id>/toggle", methods=["POST"])
@login_required
def toggle_entry(entry_id):
    """Enable/disable DNS block entry, schedule/cancel accordingly."""
    manager = _get_dns_block_manager()
    try:
        entry = manager.get_entry(entry_id)
        new_enabled = not bool(entry.get("enabled"))

        manager.toggle_entry(entry_id, new_enabled)

        scheduler = _get_dns_block_scheduler()
        if scheduler:
            if new_enabled:
                scheduler.schedule_entry(entry_id, entry["refresh_interval"])
            else:
                scheduler.cancel_entry(entry_id)

        state = "enabled" if new_enabled else "disabled"
        flash(f"DNS block entry '{entry['domain']}' {state}.")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        logger.error("Unexpected error toggling DNS block entry %d: %s", entry_id, e)
        flash("An unexpected error occurred while toggling the DNS block entry.", "error")

    return redirect(url_for("dns_blocks.index"))


@dns_block_bp.route("/dns-blocks/<int:entry_id>/refresh", methods=["POST"])
@login_required
def refresh_entry(entry_id):
    """Trigger manual refresh for a DNS block entry."""
    manager = _get_dns_block_manager()
    try:
        result = manager.refresh_entry(entry_id, trigger="manual")
        status = result.get("status", "unknown")
        if status == "success":
            flash(
                f"DNS block refreshed: {result.get('ips_added', 0)} IPs added, "
                f"{result.get('ips_removed', 0)} removed."
            )
        else:
            flash(f"DNS block refresh failed: {result.get('error', 'unknown error')}", "error")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        logger.error("Unexpected error refreshing DNS block entry %d: %s", entry_id, e)
        flash("An unexpected error occurred while refreshing the DNS block entry.", "error")

    return redirect(url_for("dns_blocks.index"))
