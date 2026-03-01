"""Dashboard routes for SOC IP Blocker."""

import logging

from flask import Blueprint, flash, jsonify, redirect, render_template, url_for

from auth import login_required
from config import Config
from database import get_db
from services.blocklist_service import BlocklistService
from services.device_manager import DeviceManager
from services.status_monitor import StatusMonitor

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def root():
    """Redirect root to dashboard."""
    return redirect(url_for("dashboard.index"))


@dashboard_bp.route("/dashboard")
@login_required
def index():
    """Fetch blocklist and devices, compute summary counts, render dashboard."""
    db_path = Config.DATABASE_PATH
    blocklist_service = BlocklistService(db_path=db_path)
    device_manager = DeviceManager(db_path=db_path)

    try:
        blocklist = blocklist_service.get_blocklist()
        # Attach feed_sources to each blocklist entry
        try:
            with get_db(db_path) as conn:
                for entry in blocklist:
                    row = conn.execute(
                        """SELECT GROUP_CONCAT(DISTINCT f.name) as feed_sources
                           FROM feed_entries fe
                           JOIN feeds f ON f.id = fe.feed_id
                           WHERE fe.ip_address = ?""",
                        (entry["ip_address"],)
                    ).fetchone()
                    sources = row["feed_sources"] if row and row["feed_sources"] else ""
                    entry["feed_sources"] = [s.strip() for s in sources.split(",") if s.strip()] if sources else []
        except Exception as e:
            logger.error("Error fetching feed sources: %s", e)
            for entry in blocklist:
                entry["feed_sources"] = []
    except Exception as e:
        logger.error("Error fetching blocklist: %s", e)
        blocklist = []

    devices_fetch_ok = False
    try:
        devices = device_manager.get_all_devices()
        devices_fetch_ok = True
    except Exception as e:
        logger.error("Error fetching devices: %s", e)
        devices = []

    # Redirect to Devices page when no devices are registered (first-startup).
    # On DB error (devices_fetch_ok=False), fall through to normal rendering (fail-open).
    if devices_fetch_ok and len(devices) == 0:
        return redirect(url_for("devices.devices_page"))

    total_blocked = len(blocklist)
    total_devices = len(devices)
    online_count = sum(1 for d in devices if d.get("status") == "online")
    offline_count = sum(1 for d in devices if d.get("status") == "offline")

    # Compute push status summary per device
    try:
        with get_db(db_path) as conn:
            for device in devices:
                row = conn.execute(
                    "SELECT COUNT(*) as synced FROM push_statuses WHERE device_id = ? AND status = 'success'",
                    (device["id"],)
                ).fetchone()
                device["synced_count"] = row["synced"] if row else 0
                device["total_blocked"] = total_blocked
    except Exception as e:
        logger.error("Error fetching push statuses: %s", e)

    return render_template(
        "dashboard.html",
        blocklist=blocklist,
        devices=devices,
        total_blocked=total_blocked,
        total_devices=total_devices,
        online_count=online_count,
        offline_count=offline_count,
    )


@dashboard_bp.route("/api/dashboard")
@login_required
def api_dashboard():
    """Return dashboard data as JSON for live polling updates."""
    db_path = Config.DATABASE_PATH
    blocklist_service = BlocklistService(db_path=db_path)
    device_manager = DeviceManager(db_path=db_path)

    try:
        blocklist = blocklist_service.get_blocklist()
        # Attach feed_sources to each blocklist entry
        try:
            with get_db(db_path) as conn:
                for entry in blocklist:
                    row = conn.execute(
                        """SELECT GROUP_CONCAT(DISTINCT f.name) as feed_sources
                           FROM feed_entries fe
                           JOIN feeds f ON f.id = fe.feed_id
                           WHERE fe.ip_address = ?""",
                        (entry["ip_address"],)
                    ).fetchone()
                    sources = row["feed_sources"] if row and row["feed_sources"] else ""
                    entry["feed_sources"] = [s.strip() for s in sources.split(",") if s.strip()] if sources else []
        except Exception:
            for entry in blocklist:
                entry["feed_sources"] = []
    except Exception:
        blocklist = []

    try:
        devices = device_manager.get_all_devices()
    except Exception:
        devices = []

    total_blocked = len(blocklist)
    total_devices = len(devices)
    online_count = sum(1 for d in devices if d.get("status") == "online")
    offline_count = sum(1 for d in devices if d.get("status") == "offline")

    try:
        with get_db(db_path) as conn:
            for device in devices:
                row = conn.execute(
                    "SELECT COUNT(*) as synced FROM push_statuses WHERE device_id = ? AND status = 'success'",
                    (device["id"],)
                ).fetchone()
                device["synced_count"] = row["synced"] if row else 0
                device["total_blocked"] = total_blocked
    except Exception:
        pass

    # Sanitize devices for JSON (remove credentials)
    safe_devices = []
    for d in devices:
        safe_devices.append({
            "id": d["id"],
            "hostname": d["hostname"],
            "device_type": d["device_type"],
            "block_method": d.get("block_method", ""),
            "status": d.get("status", "unknown"),
            "friendly_name": d.get("friendly_name", ""),
            "synced_count": d.get("synced_count", 0),
            "total_blocked": d.get("total_blocked", 0),
        })

    # Blocklist entries with push statuses
    blocklist_data = []
    for entry in blocklist:
        push_statuses = []
        for ps in entry.get("push_statuses", []):
            push_statuses.append({
                "hostname": ps.get("hostname", ""),
                "friendly_name": ps.get("friendly_name", ""),
                "device_type": ps.get("device_type", ""),
                "status": ps.get("status", ""),
                "error_message": ps.get("error_message", ""),
            })
        blocklist_data.append({
            "ip_address": entry["ip_address"],
            "added_by": entry["added_by"],
            "added_at": entry["added_at"],
            "note": entry.get("note", ""),
            "push_statuses": push_statuses,
            "feed_sources": entry.get("feed_sources", []),
        })

    return jsonify({
        "total_blocked": total_blocked,
        "total_devices": total_devices,
        "online_count": online_count,
        "offline_count": offline_count,
        "devices": safe_devices,
        "blocklist": blocklist_data,
    })

@dashboard_bp.route("/api/dashboard/clear-stats", methods=["POST"])
@login_required
def clear_stats():
    """Delete pending, in_progress, and failed push_status records (preserves success records)."""
    db_path = Config.DATABASE_PATH
    try:
        with get_db(db_path) as conn:
            conn.execute("DELETE FROM push_statuses WHERE status IN ('pending', 'in_progress', 'failed')")
        return jsonify({"success": True})
    except Exception as e:
        logger.error("Error clearing push stats: %s", e)
        return jsonify({"success": False, "message": str(e)}), 500



@dashboard_bp.route("/dashboard/refresh", methods=["POST"])
@login_required
def refresh():
    """Trigger manual status check of all devices and redirect to dashboard."""
    db_path = Config.DATABASE_PATH
    monitor = StatusMonitor(db_path=db_path)

    try:
        results = monitor.check_all_devices()
        online = sum(1 for s in results.values() if s == "online")
        offline = sum(1 for s in results.values() if s == "offline")
        flash(f"Status refresh complete: {online} online, {offline} offline.")
    except Exception as e:
        logger.error("Error during status refresh: %s", e)
        flash("Error refreshing device statuses.", "error")

    return redirect(url_for("dashboard.index"))


@dashboard_bp.route("/dashboard/refresh-all", methods=["POST"])
@login_required
def refresh_all():
    """Run health checks on all devices and queue blocklist sync via operation_queue."""
    db_path = Config.DATABASE_PATH
    monitor = StatusMonitor(db_path=db_path)
    device_manager = DeviceManager(db_path=db_path)

    try:
        # Health checks
        results = monitor.check_all_devices()
        online = sum(1 for s in results.values() if s == "online")
        offline = sum(1 for s in results.values() if s == "offline")

        # Queue sync for online devices via operation_queue
        devices = device_manager.get_all_devices()
        online_devices = [d for d in devices if results.get(d["id"]) == "online"]

        from services.rules_engine import RulesEngine
        engine = RulesEngine(db_path=db_path)
        for device in online_devices:
            engine.onboard_device(device["id"])

        sync_msg = f" Sync queued for {len(online_devices)} device(s)." if online_devices else ""
        return jsonify({
            "success": True,
            "message": f"Health check: {online} online, {offline} offline.{sync_msg}",
            "online": online,
            "offline": offline,
        })
    except Exception as e:
        logger.error("Error during dashboard refresh-all: %s", e)
        return jsonify({"success": False, "message": f"Refresh failed: {e}"}), 500
