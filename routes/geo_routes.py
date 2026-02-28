"""Geo-blocking routes for country-level IP blocking.

Provides a thin orchestration layer around FeedManager/FeedScheduler
to create and manage geo-blocking feeds using ipdeny.com zone files.
"""

import logging
from typing import Optional

from flask import Blueprint, jsonify, request

from auth import login_required
from config import Config
from routes.geo_data import COUNTRIES
from services.feed_manager import FeedManager
from services.feed_scheduler import FeedScheduler
from services.rules_engine import _write_audit_log

logger = logging.getLogger(__name__)

geo_bp = Blueprint("geo_blocks", __name__)

# Module-level references set during app initialization
_feed_scheduler: Optional[FeedScheduler] = None


def init_geo_routes(feed_scheduler: FeedScheduler):
    """Initialize module-level scheduler reference for use by routes."""
    global _feed_scheduler
    _feed_scheduler = feed_scheduler


def _get_feed_manager() -> FeedManager:
    """Create a FeedManager using the configured database path."""
    return FeedManager(db_path=Config.DATABASE_PATH)


def _get_feed_scheduler() -> Optional[FeedScheduler]:
    """Return the module-level FeedScheduler instance."""
    return _feed_scheduler


def _geo_feed_name(country_name: str, ip_version: str) -> str:
    """Return feed name like 'Geo: China (IPv4)'."""
    return f"Geo: {country_name} ({ip_version})"


def _ipv4_url(country_code: str) -> str:
    """Return ipdeny.com IPv4 aggregated zone URL."""
    return f"https://www.ipdeny.com/ipblocks/data/aggregated/{country_code}-aggregated.zone"


def _ipv6_url(country_code: str) -> str:
    """Return ipdeny.com IPv6 aggregated zone URL."""
    return f"https://www.ipdeny.com/ipv6/ipaddresses/aggregated/{country_code}-aggregated.zone"


def get_enabled_countries(feed_manager: FeedManager) -> set:
    """Return set of country codes currently enabled by scanning feed names.

    Scans all feeds for names matching the 'Geo: {Country Name} (IPv4)' pattern,
    reverse-looks up the country code from COUNTRIES, and returns the set of codes.
    Only IPv4 feeds are checked to avoid double-counting (each country has IPv4+IPv6).
    """
    feeds = feed_manager.get_all_feeds()
    enabled = set()
    for feed in feeds:
        name = feed.get("name", "")
        if name.startswith("Geo: ") and "(IPv4)" in name:
            country_name = name[5:].rsplit(" (IPv4)", 1)[0]
            for code, cname in COUNTRIES.items():
                if cname == country_name:
                    enabled.add(code)
                    break
    return enabled

@geo_bp.route("/geo-blocks/disable", methods=["POST"])
@login_required
def disable():
    """Disable geo-blocking for a country by deleting IPv4 + IPv6 feeds."""
    data = request.get_json(silent=True) or {}
    country_code = data.get("country_code", "").strip().lower()

    # Validate country code
    if country_code not in COUNTRIES:
        return jsonify({"success": False, "message": f"Unknown country code: {country_code}"}), 400

    country_name = COUNTRIES[country_code]
    feed_manager = _get_feed_manager()
    scheduler = _get_feed_scheduler()

    try:
        # Look up both feeds by name
        ipv4_name = _geo_feed_name(country_name, "IPv4")
        ipv6_name = _geo_feed_name(country_name, "IPv6")

        all_feeds = feed_manager.get_all_feeds()
        ipv4_feed = None
        ipv6_feed = None
        for feed in all_feeds:
            if feed.get("name") == ipv4_name:
                ipv4_feed = feed
            elif feed.get("name") == ipv6_name:
                ipv6_feed = feed

        if not ipv4_feed and not ipv6_feed:
            return jsonify({"success": False, "message": f"Geo-blocking is not enabled for {country_name}"}), 404

        ipv4_feed_id = ipv4_feed["id"] if ipv4_feed else None
        ipv6_feed_id = ipv6_feed["id"] if ipv6_feed else None

        # Delete feeds (triggers DiffSyncEngine IP removal)
        if ipv4_feed:
            feed_manager.delete_feed(ipv4_feed["id"])
        if ipv6_feed:
            feed_manager.delete_feed(ipv6_feed["id"])

        # Cancel scheduled refresh jobs
        if scheduler:
            if ipv4_feed_id:
                scheduler.cancel_feed(ipv4_feed_id)
            if ipv6_feed_id:
                scheduler.cancel_feed(ipv6_feed_id)

        # Write audit log
        _write_audit_log(
            Config.DATABASE_PATH,
            event_type="geo_blocking",
            action="disabled",
            details={
                "country_name": country_name,
                "country_code": country_code,
                "ipv4_feed_id": ipv4_feed_id,
                "ipv6_feed_id": ipv6_feed_id,
            },
        )

        return jsonify({"success": True, "message": f"Geo-blocking disabled for {country_name}"})
    except Exception as e:
        logger.exception("Failed to disable geo-blocking for %s", country_code)
        return jsonify({"success": False, "message": "An unexpected error occurred."}), 500


@geo_bp.route("/geo-blocks/enable", methods=["POST"])
@login_required
def enable():
    """Enable geo-blocking for a country by creating IPv4 and/or IPv6 feeds."""
    data = request.get_json(silent=True) or {}
    country_code = data.get("country_code", "").strip().lower()
    refresh_interval = data.get("refresh_interval", 86400)
    ip_versions = data.get("ip_versions", ["ipv4"])

    # Validate country code
    if country_code not in COUNTRIES:
        return jsonify({"success": False, "message": f"Unknown country code: {country_code}"}), 400

    # Validate refresh_interval
    if not isinstance(refresh_interval, int) or refresh_interval < 60 or refresh_interval > 86400:
        return jsonify({"success": False, "message": "refresh_interval must be an integer between 60 and 86400"}), 400

    # Validate ip_versions
    if not isinstance(ip_versions, list) or not ip_versions:
        ip_versions = ["ipv4"]
    ip_versions = [v.lower() for v in ip_versions if v.lower() in ("ipv4", "ipv6")]
    if not ip_versions:
        return jsonify({"success": False, "message": "At least one IP version (ipv4 or ipv6) is required"}), 400

    create_ipv4 = "ipv4" in ip_versions
    create_ipv6 = "ipv6" in ip_versions

    country_name = COUNTRIES[country_code]
    feed_manager = _get_feed_manager()
    scheduler = _get_feed_scheduler()

    ipv4_feed = None
    ipv6_feed = None
    errors = []

    try:
        # Create IPv4 feed if requested
        if create_ipv4:
            ipv4_name = _geo_feed_name(country_name, "IPv4")
            try:
                ipv4_feed = feed_manager.create_feed(ipv4_name, _ipv4_url(country_code), refresh_interval)
                try:
                    feed_manager.refresh_feed(ipv4_feed["id"], trigger="initial")
                except Exception as refresh_err:
                    logger.warning("Initial refresh for geo feed '%s' failed: %s", ipv4_name, refresh_err)
            except ValueError as e:
                logger.warning("Could not create IPv4 geo feed for %s: %s", country_code, e)
                errors.append(f"IPv4: {e}")

        # Create IPv6 feed if requested
        if create_ipv6:
            ipv6_name = _geo_feed_name(country_name, "IPv6")
            try:
                ipv6_feed = feed_manager.create_feed(ipv6_name, _ipv6_url(country_code), refresh_interval)
                try:
                    feed_manager.refresh_feed(ipv6_feed["id"], trigger="initial")
                except Exception as refresh_err:
                    logger.warning("Initial refresh for geo feed '%s' failed: %s", ipv6_name, refresh_err)
            except ValueError as e:
                logger.warning("Could not create IPv6 geo feed for %s: %s", country_code, e)
                errors.append(f"IPv6: {e}")

        # If all requested versions failed, return error
        if not ipv4_feed and not ipv6_feed:
            return jsonify({
                "success": False,
                "message": f"Could not enable geo-blocking for {country_name}: no IP data available. {'; '.join(errors)}",
            }), 400

        # Schedule successfully created feeds
        if scheduler:
            if ipv4_feed:
                scheduler.schedule_feed(ipv4_feed["id"], refresh_interval)
            if ipv6_feed:
                scheduler.schedule_feed(ipv6_feed["id"], refresh_interval)

        # Write audit log
        _write_audit_log(
            Config.DATABASE_PATH,
            event_type="geo_blocking",
            action="enabled",
            details={
                "country_name": country_name,
                "country_code": country_code,
                "ipv4_feed_id": ipv4_feed["id"] if ipv4_feed else None,
                "ipv6_feed_id": ipv6_feed["id"] if ipv6_feed else None,
            },
        )

        msg = f"Geo-blocking enabled for {country_name}"
        if errors:
            msg += f" (partial: {'; '.join(errors)})"
        return jsonify({"success": True, "message": msg})
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        logger.exception("Failed to enable geo-blocking for %s", country_code)
        return jsonify({"success": False, "message": "An unexpected error occurred."}), 500

