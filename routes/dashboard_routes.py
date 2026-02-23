"""Dashboard routes for SOC IP Blocker."""

import logging
import threading

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
    except Exception as e:
        logger.error("Error fetching blocklist: %s", e)
        blocklist = []

    try:
        devices = device_manager.get_all_devices()
    except Exception as e:
        logger.error("Error fetching devices: %s", e)
        devices = []

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
    """Run health checks on all devices and sync blocklist in background. Returns JSON."""
    db_path = Config.DATABASE_PATH
    monitor = StatusMonitor(db_path=db_path)
    device_manager = DeviceManager(db_path=db_path)
    blocklist_service = BlocklistService(db_path=db_path)

    try:
        # Health checks
        results = monitor.check_all_devices()
        online = sum(1 for s in results.values() if s == "online")
        offline = sum(1 for s in results.values() if s == "offline")

        # Sync blocklist in background for online devices
        devices = device_manager.get_all_devices()
        online_devices = [d for d in devices if results.get(d["id"]) == "online"]
        blocklist = blocklist_service.get_blocklist()
        blocked_ips = [entry["ip_address"] for entry in blocklist]

        if blocked_ips and online_devices:
            def _bg_sync():
                from services.push_engine import PushEngine
                from clients.pfsense_client import PfSenseClient
                ALIAS_NAME = "soc_blocklist"
                for device in online_devices:
                    try:
                        if device["device_type"] == "pfsense" and device.get("block_method") == "floating_rule":
                            client = PfSenseClient(
                                host=device["hostname"],
                                username=device.get("web_username", ""),
                                password=device.get("web_password", ""),
                            )
                            client.ensure_alias_exists(ALIAS_NAME, blocked_ips)
                            # Write push_statuses
                            with get_db(db_path) as conn:
                                for ip in blocked_ips:
                                    block_entry = conn.execute("SELECT id FROM block_entries WHERE ip_address = ?", (ip,)).fetchone()
                                    if block_entry:
                                        conn.execute(
                                            """INSERT OR REPLACE INTO push_statuses
                                               (block_entry_id, device_id, status, error_message, pushed_at)
                                               VALUES (?, ?, 'success', NULL, CURRENT_TIMESTAMP)""",
                                            (block_entry["id"], device["id"])
                                        )
                        else:
                            engine = PushEngine(db_path=db_path)
                            for ip in blocked_ips:
                                result = engine._push_to_device(ip, device, "block")
                                with get_db(db_path) as conn:
                                    block_entry = conn.execute("SELECT id FROM block_entries WHERE ip_address = ?", (ip,)).fetchone()
                                    if block_entry:
                                        status = "success" if result["success"] else "failed"
                                        conn.execute(
                                            """INSERT OR REPLACE INTO push_statuses
                                               (block_entry_id, device_id, status, error_message, pushed_at)
                                               VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)""",
                                            (block_entry["id"], device["id"], status, result.get("error_message"))
                                        )
                    except Exception as e:
                        logger.error("Dashboard refresh-all sync failed for %s: %s", device["hostname"], e)

            t = threading.Thread(target=_bg_sync, daemon=True)
            t.start()

        sync_msg = f" Syncing {len(blocked_ips)} IP(s) to {len(online_devices)} device(s)." if blocked_ips and online_devices else ""
        return jsonify({
            "success": True,
            "message": f"Health check: {online} online, {offline} offline.{sync_msg}",
            "online": online,
            "offline": offline,
        })
    except Exception as e:
        logger.error("Error during dashboard refresh-all: %s", e)
        return jsonify({"success": False, "message": f"Refresh failed: {e}"}), 500
