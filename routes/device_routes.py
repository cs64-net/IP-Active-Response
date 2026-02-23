"""Device management routes for adding, editing, removing, and testing devices."""

import logging

from flask import Blueprint, flash, jsonify, redirect, request, url_for

from auth import login_required
from config import Config
from services.device_manager import DeviceManager
from services.status_monitor import StatusMonitor

logger = logging.getLogger(__name__)

devices_bp = Blueprint("devices", __name__)


@devices_bp.route("/devices/add", methods=["POST"])
@login_required
def add_device():
    """Parse form and add a pfSense or Linux device. Returns JSON for AJAX, redirect for forms."""
    db_path = Config.DATABASE_PATH
    dm = DeviceManager(db_path=db_path)
    device_type = request.form.get("device_type", "").strip()
    wants_json = request.accept_mimetypes.best == "application/json" or request.headers.get("X-Requested-With") == "XMLHttpRequest"

    try:
        device = None
        if device_type == "pfsense":
            hostname = request.form.get("hostname", "").strip()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            block_method = request.form.get("block_method", "floating_rule").strip()
            friendly_name = request.form.get("friendly_name", "").strip()
            device = dm.add_pfsense(hostname, username, password, block_method, friendly_name)
            msg = f"pfSense device {hostname} added successfully."
        elif device_type == "linux":
            hostname = request.form.get("hostname", "").strip()
            port = int(request.form.get("port", 22))
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip() or None
            key_path = request.form.get("key_path", "").strip() or None
            friendly_name = request.form.get("friendly_name", "").strip()
            ssh_key = request.form.get("ssh_key", "").strip() or ""
            sudo_password = request.form.get("sudo_password", "").strip() or ""
            device = dm.add_linux(hostname, port, username, password, key_path, friendly_name, ssh_key, sudo_password=sudo_password)
            msg = f"Linux device {hostname} added successfully."
        else:
            if wants_json:
                return jsonify({"success": False, "message": "Invalid device type."}), 400
            flash("Invalid device type.", "error")
            return redirect(url_for("settings.index"))

        if wants_json:
            return jsonify({"success": True, "message": msg, "device_id": device["id"]})
        flash(msg)
    except ValueError as e:
        if wants_json:
            return jsonify({"success": False, "message": str(e)}), 400
        flash(str(e), "error")
    except Exception as e:
        logger.error("Error adding device: %s", e)
        if wants_json:
            return jsonify({"success": False, "message": "An unexpected error occurred while adding the device."}), 500
        flash("An unexpected error occurred while adding the device.", "error")

    return redirect(url_for("settings.index"))


@devices_bp.route("/devices/add-json", methods=["POST"])
@login_required
def add_device_json():
    """Purely JSON-based device add for the AJAX wizard flow."""
    db_path = Config.DATABASE_PATH
    dm = DeviceManager(db_path=db_path)

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Invalid JSON body."}), 400

    device_type = (data.get("device_type") or "").strip()

    try:
        if device_type == "pfsense":
            hostname = (data.get("hostname") or "").strip()
            username = (data.get("username") or "").strip()
            password = (data.get("password") or "").strip()
            block_method = (data.get("block_method") or "floating_rule").strip()
            friendly_name = (data.get("friendly_name") or "").strip()
            if not hostname or not username or not password:
                return jsonify({"success": False, "message": "Hostname, username, and password are required."}), 400
            device = dm.add_pfsense(hostname, username, password, block_method, friendly_name)
        elif device_type == "linux":
            hostname = (data.get("hostname") or "").strip()
            port = int(data.get("port") or 22)
            username = (data.get("username") or "").strip()
            password = (data.get("password") or "").strip() or None
            key_path = (data.get("key_path") or "").strip() or None
            friendly_name = (data.get("friendly_name") or "").strip()
            ssh_key = (data.get("ssh_key") or "").strip() or ""
            sudo_password = (data.get("sudo_password") or "").strip() or ""
            if not hostname or not username:
                return jsonify({"success": False, "message": "Hostname and username are required."}), 400
            device = dm.add_linux(hostname, port, username, password, key_path, friendly_name, ssh_key, sudo_password=sudo_password)
        else:
            return jsonify({"success": False, "message": "Invalid device type. Must be 'pfsense' or 'linux'."}), 400

        return jsonify({"success": True, "message": f"Device {hostname} added.", "device_id": device["id"]})
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        logger.error("Error adding device via JSON: %s", e)
        return jsonify({"success": False, "message": "An unexpected error occurred."}), 500


@devices_bp.route("/devices/edit/<int:device_id>", methods=["POST"])
@login_required
def edit_device(device_id):
    """Update device configuration from form fields."""
    db_path = Config.DATABASE_PATH
    dm = DeviceManager(db_path=db_path)

    fields = {}
    for key in ("hostname", "web_username", "web_password", "block_method",
                "ssh_username", "ssh_password", "ssh_key_path", "friendly_name", "ssh_key", "sudo_password"):
        val = request.form.get(key, "").strip()
        if val:
            fields[key] = val

    port_val = request.form.get("ssh_port", "").strip()
    if port_val:
        fields["ssh_port"] = int(port_val)

    try:
        dm.update_device(device_id, **fields)
        flash("Device updated successfully.")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        logger.error("Error editing device %s: %s", device_id, e)
        flash("An unexpected error occurred while updating the device.", "error")

    return redirect(url_for("settings.index"))

def _cleanup_device(device, db_path):
    """Remove all block rules/routes from a device before deletion."""
    from services.blocklist_service import BlocklistService
    blocklist_service = BlocklistService(db_path=db_path)
    blocklist = blocklist_service.get_blocklist()
    blocked_ips = [entry["ip_address"] for entry in blocklist]

    if not blocked_ips:
        return

    if device["device_type"] == "pfsense":
        from clients.pfsense_client import PfSenseClient
        client = PfSenseClient(
            host=device["hostname"],
            username=device.get("web_username", ""),
            password=device.get("web_password", ""),
        )
        if device.get("block_method") == "floating_rule":
            # Remove floating rules first, then alias
            try:
                client.remove_floating_rules("soc_blocklist")
            except Exception as e:
                logger.warning("Failed to remove floating rules on %s: %s", device["hostname"], e)
            try:
                client.remove_alias("soc_blocklist")
            except Exception as e:
                logger.warning("Failed to remove alias on %s: %s", device["hostname"], e)
        else:
            # Remove null routes
            for ip in blocked_ips:
                try:
                    client.remove_null_route(ip)
                except Exception as e:
                    logger.warning("Failed to remove null route for %s on %s: %s", ip, device["hostname"], e)
    elif device["device_type"] == "linux":
        from clients.linux_client import LinuxClient
        client = LinuxClient(
            host=device["hostname"],
            port=device.get("ssh_port", 22),
            username=device.get("ssh_username", ""),
            password=device.get("ssh_password"),
            key_path=device.get("ssh_key_path"),
            key_content=device.get("ssh_key"),
            sudo_password=device.get("sudo_password"),
        )
        try:
            client.remove_null_routes_bulk(blocked_ips)
        except Exception as e:
            logger.warning("Failed to remove null routes on %s: %s", device["hostname"], e)



@devices_bp.route("/devices/remove/<int:device_id>", methods=["POST"])
@login_required
def remove_device(device_id):
    """Remove a device from the registry, optionally cleaning up rules on the device."""
    db_path = Config.DATABASE_PATH
    dm = DeviceManager(db_path=db_path)

    # Support JSON body for cleanup option
    cleanup = False
    is_json = request.is_json
    if is_json:
        data = request.get_json(silent=True) or {}
        cleanup = data.get("cleanup", False)

    try:
        # Get device info before deletion (needed for cleanup)
        devices = dm.get_all_devices()
        device = next((d for d in devices if d["id"] == device_id), None)
        if device is None:
            if is_json:
                return jsonify({"success": False, "message": f"Device {device_id} not found."}), 404
            flash("Device not found.", "error")
            return redirect(url_for("settings.index"))

        # Cleanup rules/routes on the device if requested
        if cleanup:
            try:
                _cleanup_device(device, db_path)
            except Exception as e:
                logger.warning("Cleanup failed for device %s: %s", device_id, e)
                # Continue with removal even if cleanup fails

        dm.remove_device(device_id)

        msg = "Device removed successfully."
        if cleanup:
            msg = "Device removed and rules cleaned up."

        if is_json:
            return jsonify({"success": True, "message": msg})
        flash(msg)
    except ValueError as e:
        if is_json:
            return jsonify({"success": False, "message": str(e)}), 400
        flash(str(e), "error")
    except Exception as e:
        logger.error("Error removing device %s: %s", device_id, e)
        if is_json:
            return jsonify({"success": False, "message": f"Failed to remove device: {e}"}), 500
        flash("An unexpected error occurred while removing the device.", "error")

    return redirect(url_for("settings.index"))


@devices_bp.route("/devices/test/<int:device_id>", methods=["POST"])
@login_required
def test_device(device_id):
    """Test connectivity to a device and return JSON result."""
    db_path = Config.DATABASE_PATH
    dm = DeviceManager(db_path=db_path)
    monitor = StatusMonitor(db_path=db_path)

    try:
        devices = dm.get_all_devices()
        device = next((d for d in devices if d["id"] == device_id), None)
        if device is None:
            return jsonify({"success": False, "message": f"Device {device_id} not found."}), 404

        status = monitor.check_device(device)

        # Persist status to DB so the GUI reflects it immediately
        from datetime import datetime, timezone
        from database import get_db
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        with get_db(db_path) as conn:
            conn.execute(
                "UPDATE managed_devices SET status = ?, last_checked = ? WHERE id = ?",
                (status, now, device_id),
            )

        success = status == "online"
        message = "Connection successful." if success else "Connection failed."
        return jsonify({"success": success, "message": message, "status": status})
    except Exception as e:
        logger.error("Error testing device %s: %s", device_id, e)
        return jsonify({"success": False, "message": str(e)}), 500

@devices_bp.route("/devices/validate-credentials", methods=["POST"])
@login_required
def validate_credentials():
    """Validate device credentials before adding. Returns JSON."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Invalid request."}), 400

    device_type = (data.get("device_type") or "").strip()
    hostname = (data.get("hostname") or "").strip()

    if not hostname:
        return jsonify({"success": False, "message": "Hostname is required."}), 400

    try:
        if device_type == "pfsense":
            username = (data.get("username") or "").strip()
            password = (data.get("password") or "").strip()
            if not username or not password:
                return jsonify({"success": False, "message": "Username and password are required."}), 400

            from clients.pfsense_client import PfSenseClient, PfSenseError
            client = PfSenseClient(host=hostname, username=username, password=password)
            try:
                client.login(timeout=10)
                return jsonify({"success": True, "message": "Login successful — credentials are valid."})
            except PfSenseError as e:
                return jsonify({"success": False, "message": f"Login failed: {e}"}), 400

        elif device_type == "linux":
            username = (data.get("username") or "").strip()
            password = (data.get("password") or "").strip() or None
            ssh_key = (data.get("ssh_key") or "").strip() or None
            port = int(data.get("port") or 22)

            if not username:
                return jsonify({"success": False, "message": "SSH username is required."}), 400
            if not password and not ssh_key:
                return jsonify({"success": False, "message": "SSH password or key is required."}), 400

            from clients.linux_client import LinuxClient, LinuxClientError
            client = LinuxClient(host=hostname, port=port, username=username,
                                 password=password, key_content=ssh_key)
            try:
                ssh = client._get_ssh_client()
                ssh.close()
                return jsonify({"success": True, "message": "SSH connection successful — credentials are valid."})
            except LinuxClientError as e:
                return jsonify({"success": False, "message": f"SSH connection failed: {e}"}), 400
            except Exception as e:
                return jsonify({"success": False, "message": f"Connection failed: {e}"}), 400
        else:
            return jsonify({"success": False, "message": "Invalid device type."}), 400
    except Exception as e:
        logger.error("Error validating credentials: %s", e)
        return jsonify({"success": False, "message": f"Validation error: {e}"}), 500

