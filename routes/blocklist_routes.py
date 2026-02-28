"""Blocklist routes for adding and removing IPs."""

import logging

from flask import Blueprint, flash, jsonify, redirect, request, session, url_for

from auth import login_required
from config import Config
from services.rules_engine import RulesEngine

logger = logging.getLogger(__name__)

blocklist_bp = Blueprint("blocklist", __name__)


@blocklist_bp.route("/blocklist/add", methods=["POST"])
@login_required
def add_ip():
    """Add an IP to the blocklist. Operations are enqueued asynchronously."""
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
    engine = RulesEngine(db_path=db_path)

    try:
        result = engine.process_block([ip_address], user, note)

        if result["errors"]:
            error_msg = "; ".join(result["errors"])
            if request.is_json:
                return jsonify({"success": False, "message": error_msg}), 400
            flash(error_msg, "error")
            return redirect(url_for("dashboard.index"))

        added = result["ips_added"]
        operation_id = result["operation_id"]
        display_ip = added[0] if added else ip_address

        if request.is_json:
            return jsonify({
                "success": True,
                "message": f"IP {display_ip} added to blocklist.",
                "operation_id": operation_id,
            })
        flash(f"IP {display_ip} added to blocklist.")
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


@blocklist_bp.route("/blocklist/add-bulk", methods=["POST"])
@login_required
def add_bulk():
    """Add multiple IPs to the blocklist in a single request."""
    if not request.is_json:
        return jsonify({"success": False, "message": "JSON request body required."}), 400

    data = request.get_json()
    ip_addresses = data.get("ip_addresses", [])
    note = (data.get("note") or "").strip()

    if not isinstance(ip_addresses, list) or not ip_addresses:
        return jsonify({"success": False, "message": "ip_addresses must be a non-empty list."}), 400

    user = session.get("user", "unknown")
    db_path = Config.DATABASE_PATH
    engine = RulesEngine(db_path=db_path)

    try:
        result = engine.process_block(ip_addresses, user, note)

        if result["errors"]:
            return jsonify({
                "success": False,
                "message": "; ".join(result["errors"]),
                "errors": result["errors"],
                "operation_id": result["operation_id"],
            }), 400

        return jsonify({
            "success": True,
            "message": f"{len(result['ips_added'])} IP(s) added to blocklist.",
            "ips_added": result["ips_added"],
            "operation_id": result["operation_id"],
        })
    except Exception as e:
        logger.error("Unexpected error in bulk add: %s", e)
        return jsonify({"success": False, "message": "An unexpected error occurred."}), 500


@blocklist_bp.route("/blocklist/remove/<path:ip>", methods=["POST"])
@login_required
def remove_ip(ip):
    """Remove an IP from the blocklist. Removal operations are enqueued asynchronously."""
    user = session.get("user", "unknown")
    db_path = Config.DATABASE_PATH
    engine = RulesEngine(db_path=db_path)

    try:
        result = engine.process_unblock([ip], user)

        if result["errors"]:
            error_msg = "; ".join(result["errors"])
            if request.is_json:
                return jsonify({"success": False, "message": error_msg}), 400
            flash(error_msg, "error")
            return redirect(url_for("dashboard.index"))

        operation_id = result["operation_id"]

        if request.is_json:
            return jsonify({
                "success": True,
                "message": f"IP {ip} removed from blocklist.",
                "operation_id": operation_id,
            })
        flash(f"IP {ip} removed from blocklist.")
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

@blocklist_bp.route("/blocklist/remove-bulk", methods=["POST"])
@login_required
def remove_bulk():
    """Remove multiple IPs from the blocklist in a single request."""
    if not request.is_json:
        return jsonify({"success": False, "message": "JSON request body required."}), 400

    data = request.get_json()
    ip_addresses = data.get("ip_addresses", [])

    if not isinstance(ip_addresses, list) or not ip_addresses:
        return jsonify({"success": False, "message": "ip_addresses must be a non-empty list."}), 400

    user = session.get("user", "unknown")
    db_path = Config.DATABASE_PATH
    engine = RulesEngine(db_path=db_path)

    try:
        result = engine.process_unblock(ip_addresses, user)

        if result["errors"]:
            return jsonify({
                "success": False,
                "message": "; ".join(result["errors"]),
                "errors": result["errors"],
                "operation_id": result["operation_id"],
            }), 400

        return jsonify({
            "success": True,
            "message": f"{len(result['ips_removed'])} IP(s) removed from blocklist.",
            "ips_removed": result["ips_removed"],
            "operation_id": result["operation_id"],
        })
    except Exception as e:
        logger.error("Unexpected error in bulk remove: %s", e)
        return jsonify({"success": False, "message": "An unexpected error occurred."}), 500

