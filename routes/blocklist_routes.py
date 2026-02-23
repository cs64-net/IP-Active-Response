"""Blocklist routes for adding and removing IPs."""

import logging
import threading

from flask import Blueprint, flash, jsonify, redirect, request, session, url_for

from auth import login_required
from config import Config
from database import get_db
from services.blocklist_service import BlocklistService
from services.device_manager import DeviceManager
from services.push_engine import PushEngine

logger = logging.getLogger(__name__)

blocklist_bp = Blueprint("blocklist", __name__)


def _push_in_background(ip_address, devices, action, db_path, block_entry_id=None):
    """Run push/remove in a background thread so the request returns immediately."""
    try:
        engine = PushEngine(db_path=db_path)
        if action == "block":
            engine.push_block(ip_address, devices)
        else:
            engine.remove_block(ip_address, devices, block_entry_id=block_entry_id)
        logger.info("Background %s for %s completed on %d device(s)", action, ip_address, len(devices))
    except Exception as e:
        logger.error("Background %s for %s failed: %s", action, ip_address, e)


@blocklist_bp.route("/blocklist/add", methods=["POST"])
@login_required
def add_ip():
    """Add an IP to the blocklist. Push to devices happens in background."""
    # Support both form and JSON
    if request.is_json:
        data = request.get_json()
        ip_address = (data.get("ip_address") or "").strip()
        note = (data.get("note") or "").strip()
    else:
        ip_address = request.form.get("ip_address", "").strip()
        note = request.form.get("note", "").strip()

    user = session.get("user", "unknown")
    db_path = Config.DATABASE_PATH
    blocklist_service = BlocklistService(db_path=db_path)
    device_manager = DeviceManager(db_path=db_path)

    try:
        entry = blocklist_service.add_ip(ip_address, user, note)
        normalized_ip = entry["ip_address"]
        devices = device_manager.get_all_devices()

        # Push to devices in background thread (use normalized IP)
        if devices:
            t = threading.Thread(
                target=_push_in_background,
                args=(normalized_ip, devices, "block", db_path),
                daemon=True,
            )
            t.start()

        if request.is_json:
            return jsonify({
                "success": True,
                "message": f"IP {normalized_ip} added to blocklist. Pushing to {len(devices)} device(s) in background.",
            })
        flash(f"IP {normalized_ip} added to blocklist. Pushing to {len(devices)} device(s) in background.")
    except ValueError as e:
        if request.is_json:
            return jsonify({"success": False, "message": str(e)}), 400
        flash(str(e), "error")
    except Exception as e:
        logger.error("Unexpected error adding IP %s: %s", ip_address, e)
        if request.is_json:
            return jsonify({"success": False, "message": "An unexpected error occurred."}), 500
        flash("An unexpected error occurred while adding the IP.", "error")

    return redirect(url_for("dashboard.index"))


@blocklist_bp.route("/blocklist/remove/<path:ip>", methods=["POST"])
@login_required
def remove_ip(ip):
    """Remove an IP from the blocklist. Device removal happens in background."""
    db_path = Config.DATABASE_PATH
    blocklist_service = BlocklistService(db_path=db_path)
    device_manager = DeviceManager(db_path=db_path)

    try:
        devices = device_manager.get_all_devices()

        # Grab block_entry_id before deleting the DB row
        # so the background thread can still store push statuses
        block_entry_id = None
        with get_db(db_path) as conn:
            row = conn.execute(
                "SELECT id FROM block_entries WHERE ip_address = ?", (ip,)
            ).fetchone()
            if row:
                block_entry_id = row["id"]

        # Delete from DB first (deterministic, no race)
        blocklist_service.remove_ip(ip)

        # Then push removal to devices in background
        if devices:
            t = threading.Thread(
                target=_push_in_background,
                args=(ip, devices, "remove", db_path),
                kwargs={"block_entry_id": block_entry_id},
                daemon=True,
            )
            t.start()

        if request.is_json:
            return jsonify({
                "success": True,
                "message": f"IP {ip} removed. Cleaning up {len(devices)} device(s) in background.",
            })
        flash(f"IP {ip} removed. Cleaning up {len(devices)} device(s) in background.")
    except ValueError as e:
        if request.is_json:
            return jsonify({"success": False, "message": str(e)}), 400
        flash(str(e), "error")
    except Exception as e:
        logger.error("Unexpected error removing IP %s: %s", ip, e)
        if request.is_json:
            return jsonify({"success": False, "message": "An unexpected error occurred."}), 500
        flash("An unexpected error occurred while removing the IP.", "error")

    return redirect(url_for("dashboard.index"))
