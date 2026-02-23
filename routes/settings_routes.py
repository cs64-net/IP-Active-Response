"""Settings routes for app configuration and floating rule management."""

import logging
import threading

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for

from auth import login_required
from config import Config
from database import get_db
from services.blocklist_service import BlocklistService
from services.device_manager import DeviceManager
from services.status_monitor import StatusMonitor
from clients.pfsense_client import PfSenseClient

logger = logging.getLogger(__name__)

settings_bp = Blueprint("settings", __name__)

ALIAS_NAME = "soc_blocklist"


@settings_bp.route("/settings")
@login_required
def index():
    """Render settings page with devices list and current app settings."""
    db_path = Config.DATABASE_PATH
    device_manager = DeviceManager(db_path=db_path)

    try:
        devices = device_manager.get_all_devices()
    except Exception as e:
        logger.error("Error fetching devices: %s", e)
        devices = []

    try:
        with get_db(db_path) as conn:
            row = conn.execute(
                "SELECT monitor_interval, default_block_method, protected_ranges FROM app_settings WHERE id = 1"
            ).fetchone()
            settings = dict(row) if row else {"monitor_interval": 300, "default_block_method": "null_route", "protected_ranges": ""}
    except Exception as e:
        logger.error("Error fetching app settings: %s", e)
        settings = {"monitor_interval": 300, "default_block_method": "null_route", "protected_ranges": ""}

    return render_template("settings.html", devices=devices, settings=settings)


@settings_bp.route("/settings/update", methods=["POST"])
@login_required
def update():
    """Validate and save app settings (monitor interval)."""
    db_path = Config.DATABASE_PATH

    monitor_interval = request.form.get("monitor_interval", "").strip()

    # Validate monitor_interval
    try:
        interval_val = int(monitor_interval)
        if interval_val <= 0:
            raise ValueError()
    except (ValueError, TypeError):
        flash("Monitor interval must be a positive integer.", "error")
        return redirect(url_for("settings.index"))

    try:
        with get_db(db_path) as conn:
            conn.execute(
                "UPDATE app_settings SET monitor_interval = ? WHERE id = 1",
                (interval_val,),
            )
        flash("Settings updated successfully.")
    except Exception as e:
        logger.error("Error saving settings: %s", e)
        flash("An unexpected error occurred while saving settings.", "error")

    return redirect(url_for("settings.index"))


@settings_bp.route("/settings/protected-ranges")
@login_required
def get_protected_ranges():
    """Return current protected IP ranges as JSON list."""
    db_path = Config.DATABASE_PATH
    try:
        with get_db(db_path) as conn:
            row = conn.execute(
                "SELECT protected_ranges FROM app_settings WHERE id = 1"
            ).fetchone()
            raw = row["protected_ranges"] if row and row["protected_ranges"] else ""
            ranges = [r.strip() for r in raw.split("\n") if r.strip()]
        return jsonify({"ranges": ranges})
    except Exception as e:
        logger.error("Error fetching protected ranges: %s", e)
        return jsonify({"ranges": []})


@settings_bp.route("/settings/protected-ranges/add", methods=["POST"])
@login_required
def add_protected_range():
    """Add a single protected IP range."""
    import ipaddress as _ipaddress

    db_path = Config.DATABASE_PATH
    data = request.get_json(silent=True) or {}
    new_range = (data.get("range") or "").strip()

    if not new_range:
        return jsonify({"success": False, "message": "No range provided."})

    try:
        network = _ipaddress.ip_network(new_range, strict=False)
        normalized = str(network)
    except ValueError:
        return jsonify({"success": False, "message": f"Invalid range: '{new_range}'. Use CIDR notation (e.g. 10.0.0.0/8)."})

    try:
        with get_db(db_path) as conn:
            row = conn.execute(
                "SELECT protected_ranges FROM app_settings WHERE id = 1"
            ).fetchone()
            raw = row["protected_ranges"] if row and row["protected_ranges"] else ""
            existing = [r.strip() for r in raw.split("\n") if r.strip()]

            if normalized in existing:
                return jsonify({"success": False, "message": f"Range {normalized} already exists."})

            existing.append(normalized)
            conn.execute(
                "UPDATE app_settings SET protected_ranges = ? WHERE id = 1",
                ("\n".join(existing),),
            )
        return jsonify({"success": True, "message": f"Added {normalized}."})
    except Exception as e:
        logger.error("Error adding protected range: %s", e)
        return jsonify({"success": False, "message": "An unexpected error occurred."})


@settings_bp.route("/settings/protected-ranges/remove", methods=["POST"])
@login_required
def remove_protected_range():
    """Remove a single protected IP range."""
    db_path = Config.DATABASE_PATH
    data = request.get_json(silent=True) or {}
    target = (data.get("range") or "").strip()

    if not target:
        return jsonify({"success": False, "message": "No range provided."})

    try:
        with get_db(db_path) as conn:
            row = conn.execute(
                "SELECT protected_ranges FROM app_settings WHERE id = 1"
            ).fetchone()
            raw = row["protected_ranges"] if row and row["protected_ranges"] else ""
            existing = [r.strip() for r in raw.split("\n") if r.strip()]

            if target not in existing:
                return jsonify({"success": False, "message": f"Range {target} not found."})

            existing = [r for r in existing if r != target]
            conn.execute(
                "UPDATE app_settings SET protected_ranges = ? WHERE id = 1",
                ("\n".join(existing),),
            )
        return jsonify({"success": True, "message": f"Removed {target}."})
    except Exception as e:
        logger.error("Error removing protected range: %s", e)
        return jsonify({"success": False, "message": "An unexpected error occurred."})


@settings_bp.route("/settings/floating-rule/<int:device_id>", methods=["POST"])
@login_required
def create_floating_rule(device_id):
    """Trigger Central Floating Rule creation on specified pfSense device.

    Returns JSON response for async frontend handling.
    """
    db_path = Config.DATABASE_PATH
    device_manager = DeviceManager(db_path=db_path)
    blocklist_service = BlocklistService(db_path=db_path)

    try:
        devices = device_manager.get_all_devices()
        device = next((d for d in devices if d["id"] == device_id), None)

        if device is None:
            return jsonify({"success": False, "message": f"Device {device_id} not found."}), 404

        if device["device_type"] != "pfsense":
            return jsonify({"success": False, "message": "Floating rules can only be created on pfSense devices."}), 400

        # Get all blocked IPs
        blocklist = blocklist_service.get_blocklist()
        blocked_ips = [entry["ip_address"] for entry in blocklist]

        # Create pfSense client and execute
        client = PfSenseClient(
            host=device["hostname"],
            username=device.get("web_username", ""),
            password=device.get("web_password", ""),
        )
        client.ensure_alias_exists(ALIAS_NAME, blocked_ips)
        client.create_floating_rule(ALIAS_NAME)

        msg = f"Inbound + Outbound floating rules created on {device['hostname']} with {len(blocked_ips)} blocked IP(s)."
        logger.info(msg)
        return jsonify({"success": True, "message": msg})
    except Exception as e:
        logger.error("Error creating floating rule on device %s: %s", device_id, e)
        return jsonify({"success": False, "message": f"Failed to create floating rule: {e}"}), 500


@settings_bp.route("/settings/sync/<int:device_id>", methods=["POST"])
@login_required
def sync_device(device_id):
    """Sync all current blocked IPs to a device. Useful for newly added firewalls."""
    db_path = Config.DATABASE_PATH
    device_manager = DeviceManager(db_path=db_path)
    blocklist_service = BlocklistService(db_path=db_path)

    try:
        devices = device_manager.get_all_devices()
        device = next((d for d in devices if d["id"] == device_id), None)

        if device is None:
            return jsonify({"success": False, "message": f"Device {device_id} not found."}), 404

        blocklist = blocklist_service.get_blocklist()
        blocked_ips = [entry["ip_address"] for entry in blocklist]

        if not blocked_ips:
            return jsonify({"success": True, "message": "Blocklist is empty — nothing to sync."})

        def _sync_worker():
            try:
                if device["device_type"] == "pfsense" and device.get("block_method") == "floating_rule":
                    # For alias-based blocking, replace the entire alias (idempotent)
                    client = PfSenseClient(
                        host=device["hostname"],
                        username=device.get("web_username", ""),
                        password=device.get("web_password", ""),
                    )
                    client.ensure_alias_exists(ALIAS_NAME, blocked_ips)
                    logger.info("Sync complete: replaced alias with %d IPs on %s", len(blocked_ips), device["hostname"])
                    # Update push statuses for alias sync
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
                elif device["device_type"] == "linux":
                    # Use bulk operation for Linux devices (single SSH session)
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
                    bulk_result = client.add_null_routes_bulk(blocked_ips)
                    with get_db(db_path) as conn:
                        for ip in bulk_result["success"]:
                            block_entry = conn.execute("SELECT id FROM block_entries WHERE ip_address = ?", (ip,)).fetchone()
                            if block_entry:
                                conn.execute(
                                    """INSERT OR REPLACE INTO push_statuses
                                       (block_entry_id, device_id, status, error_message, pushed_at)
                                       VALUES (?, ?, 'success', NULL, CURRENT_TIMESTAMP)""",
                                    (block_entry["id"], device["id"])
                                )
                        for fail in bulk_result["failed"]:
                            block_entry = conn.execute("SELECT id FROM block_entries WHERE ip_address = ?", (fail["ip"],)).fetchone()
                            if block_entry:
                                conn.execute(
                                    """INSERT OR REPLACE INTO push_statuses
                                       (block_entry_id, device_id, status, error_message, pushed_at)
                                       VALUES (?, ?, 'failed', ?, CURRENT_TIMESTAMP)""",
                                    (block_entry["id"], device["id"], fail["error"])
                                )
                    logger.info("Sync complete: pushed %d IPs to %s", len(blocked_ips), device["hostname"])
                else:
                    # For pfSense null_route, push per-IP
                    from services.push_engine import PushEngine
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
                    logger.info("Sync complete: pushed %d IPs to %s", len(blocked_ips), device["hostname"])
            except Exception as e:
                logger.error("Sync failed for device %s: %s", device_id, e)

        t = threading.Thread(target=_sync_worker, daemon=True)
        t.start()

        return jsonify({
            "success": True,
            "message": f"Syncing {len(blocked_ips)} IP(s) to {device['hostname']} in background.",
        })
    except Exception as e:
        logger.error("Error syncing device %s: %s", device_id, e)
        return jsonify({"success": False, "message": f"Sync failed: {e}"}), 500


@settings_bp.route("/settings/refresh-all", methods=["POST"])
@login_required
def refresh_all():
    """Health check + sync blocklist for all devices. Returns JSON summary."""
    db_path = Config.DATABASE_PATH
    device_manager = DeviceManager(db_path=db_path)
    monitor = StatusMonitor(db_path=db_path)
    blocklist_service = BlocklistService(db_path=db_path)

    try:
        devices = device_manager.get_all_devices()
        if not devices:
            return jsonify({"success": True, "message": "No devices registered.", "results": []})

        blocklist = blocklist_service.get_blocklist()
        blocked_ips = [entry["ip_address"] for entry in blocklist]

        # Health check all devices first
        health_results = {}
        for device in devices:
            status = monitor.check_device(device)
            health_results[device["id"]] = status
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            with get_db(db_path) as conn:
                conn.execute(
                    "UPDATE managed_devices SET status = ?, last_checked = ? WHERE id = ?",
                    (status, now, device["id"]),
                )

        # Sync blocklist in background for online devices
        online_devices = [d for d in devices if health_results.get(d["id"]) == "online"]

        def _bg_sync():
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
                    elif device["device_type"] == "linux":
                        # Use bulk operation for Linux devices (single SSH session)
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
                        bulk_result = client.add_null_routes_bulk(blocked_ips)
                        with get_db(db_path) as conn:
                            for ip in bulk_result["success"]:
                                block_entry = conn.execute("SELECT id FROM block_entries WHERE ip_address = ?", (ip,)).fetchone()
                                if block_entry:
                                    conn.execute(
                                        """INSERT OR REPLACE INTO push_statuses
                                           (block_entry_id, device_id, status, error_message, pushed_at)
                                           VALUES (?, ?, 'success', NULL, CURRENT_TIMESTAMP)""",
                                        (block_entry["id"], device["id"])
                                    )
                            for fail in bulk_result["failed"]:
                                block_entry = conn.execute("SELECT id FROM block_entries WHERE ip_address = ?", (fail["ip"],)).fetchone()
                                if block_entry:
                                    conn.execute(
                                        """INSERT OR REPLACE INTO push_statuses
                                           (block_entry_id, device_id, status, error_message, pushed_at)
                                           VALUES (?, ?, 'failed', ?, CURRENT_TIMESTAMP)""",
                                        (block_entry["id"], device["id"], fail["error"])
                                    )
                    else:
                        # For pfSense null_route, push per-IP
                        from services.push_engine import PushEngine
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
                    logger.info("Refresh-all sync complete for %s", device["hostname"])
                except Exception as e:
                    logger.error("Refresh-all sync failed for %s: %s", device["hostname"], e)

        if blocked_ips and online_devices:
            t = threading.Thread(target=_bg_sync, daemon=True)
            t.start()

        online = sum(1 for s in health_results.values() if s == "online")
        offline = sum(1 for s in health_results.values() if s == "offline")
        sync_msg = f" Syncing {len(blocked_ips)} IP(s) to {len(online_devices)} online device(s)." if blocked_ips and online_devices else ""

        return jsonify({
            "success": True,
            "message": f"Health check: {online} online, {offline} offline.{sync_msg}",
            "online": online,
            "offline": offline,
            "syncing": len(online_devices) if blocked_ips else 0,
        })
    except Exception as e:
        logger.error("Error in refresh-all: %s", e)
        return jsonify({"success": False, "message": f"Refresh failed: {e}"}), 500


@settings_bp.route("/settings/setup-device/<int:device_id>", methods=["POST"])
@login_required
def setup_device(device_id):
    """Test connectivity, optionally create floating rules, and sync blocklist."""
    db_path = Config.DATABASE_PATH
    device_manager = DeviceManager(db_path=db_path)
    blocklist_service = BlocklistService(db_path=db_path)
    monitor = StatusMonitor(db_path=db_path)

    try:
        devices = device_manager.get_all_devices()
        device = next((d for d in devices if d["id"] == device_id), None)
        if device is None:
            return jsonify({"success": False, "message": f"Device {device_id} not found."}), 404

        steps = []

        # Step 1: Test connectivity
        status = monitor.check_device(device)
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        with get_db(db_path) as conn:
            conn.execute(
                "UPDATE managed_devices SET status = ?, last_checked = ? WHERE id = ?",
                (status, now, device["id"]),
            )
        steps.append({"step": "Connectivity Test", "success": status == "online", "message": f"Device is {status}."})

        if status != "online":
            return jsonify({"success": False, "message": "Device is offline.", "steps": steps})

        data = request.get_json(silent=True) or {}
        create_rules = data.get("create_floating_rules", False)
        sync_blocklist = data.get("sync_blocklist", False)

        # Step 2: Create floating rules if pfSense + floating_rule
        if create_rules and device["device_type"] == "pfsense" and device.get("block_method") == "floating_rule":
            try:
                blocklist = blocklist_service.get_blocklist()
                blocked_ips = [entry["ip_address"] for entry in blocklist]
                client = PfSenseClient(
                    host=device["hostname"],
                    username=device.get("web_username", ""),
                    password=device.get("web_password", ""),
                )
                client.ensure_alias_exists(ALIAS_NAME, blocked_ips)
                client.create_floating_rule(ALIAS_NAME)
                steps.append({"step": "Floating Rules", "success": True, "message": f"Floating rules created with {len(blocked_ips)} IP(s)."})
            except Exception as e:
                steps.append({"step": "Floating Rules", "success": False, "message": str(e)})

        # Step 3: Sync blocklist
        if sync_blocklist:
            try:
                blocklist = blocklist_service.get_blocklist()
                blocked_ips = [entry["ip_address"] for entry in blocklist]
                if blocked_ips:
                    def _setup_sync():
                        try:
                            if device["device_type"] == "pfsense" and device.get("block_method") == "floating_rule":
                                client = PfSenseClient(
                                    host=device["hostname"],
                                    username=device.get("web_username", ""),
                                    password=device.get("web_password", ""),
                                )
                                client.ensure_alias_exists(ALIAS_NAME, blocked_ips)
                                # Write push_statuses for all synced IPs
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
                            elif device["device_type"] == "linux":
                                # Use bulk operation for Linux devices (single SSH session)
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
                                bulk_result = client.add_null_routes_bulk(blocked_ips)
                                with get_db(db_path) as conn:
                                    for ip in bulk_result["success"]:
                                        block_entry = conn.execute("SELECT id FROM block_entries WHERE ip_address = ?", (ip,)).fetchone()
                                        if block_entry:
                                            conn.execute(
                                                """INSERT OR REPLACE INTO push_statuses
                                                   (block_entry_id, device_id, status, error_message, pushed_at)
                                                   VALUES (?, ?, 'success', NULL, CURRENT_TIMESTAMP)""",
                                                (block_entry["id"], device["id"])
                                            )
                                    for fail in bulk_result["failed"]:
                                        block_entry = conn.execute("SELECT id FROM block_entries WHERE ip_address = ?", (fail["ip"],)).fetchone()
                                        if block_entry:
                                            conn.execute(
                                                """INSERT OR REPLACE INTO push_statuses
                                                   (block_entry_id, device_id, status, error_message, pushed_at)
                                                   VALUES (?, ?, 'failed', ?, CURRENT_TIMESTAMP)""",
                                                (block_entry["id"], device["id"], fail["error"])
                                            )
                            else:
                                # For pfSense null_route, push per-IP
                                from services.push_engine import PushEngine
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
                            logger.info("Setup sync complete for device %s", device_id)
                        except Exception as e:
                            logger.error("Setup sync failed for device %s: %s", device_id, e)

                    t = threading.Thread(target=_setup_sync, daemon=True)
                    t.start()
                    steps.append({"step": "Blocklist Sync", "success": True, "message": f"Syncing {len(blocked_ips)} IP(s) in background."})
                else:
                    steps.append({"step": "Blocklist Sync", "success": True, "message": "Blocklist empty, nothing to sync."})
            except Exception as e:
                steps.append({"step": "Blocklist Sync", "success": False, "message": str(e)})

        all_ok = all(s["success"] for s in steps)
        return jsonify({"success": all_ok, "steps": steps, "message": "Setup complete." if all_ok else "Setup completed with issues."})
    except Exception as e:
        logger.error("Error in setup-device %s: %s", device_id, e)
        return jsonify({"success": False, "message": f"Setup failed: {e}"}), 500


@settings_bp.route("/settings/switch-block-method/<int:device_id>", methods=["POST"])
@login_required
def switch_block_method(device_id):
    """Switch a pfSense device between floating_rule and null_route block methods.

    Handles cleanup of old method and setup of new method:
    - floating_rule → null_route: remove floating rules + alias, add null routes
    - null_route → floating_rule: remove null routes, create alias + floating rules
    """
    db_path = Config.DATABASE_PATH
    device_manager = DeviceManager(db_path=db_path)
    blocklist_service = BlocklistService(db_path=db_path)

    try:
        logger.info("switch_block_method called for device %s", device_id)
        devices = device_manager.get_all_devices()
        device = next((d for d in devices if d["id"] == device_id), None)
        if device is None:
            return jsonify({"success": False, "message": f"Device {device_id} not found."}), 404

        if device["device_type"] != "pfsense":
            return jsonify({"success": False, "message": "Block method switching is only for pfSense devices."}), 400

        data = request.get_json(silent=True) or {}
        new_method = data.get("new_method", "").strip()
        cleanup_old = data.get("cleanup_old", True)
        if new_method not in ("null_route", "floating_rule"):
            return jsonify({"success": False, "message": "Invalid block method."}), 400

        old_method = device.get("block_method", "null_route")
        if old_method == new_method:
            return jsonify({"success": True, "message": "Block method is already set to " + new_method + "."})

        logger.info("Switching device %s from %s to %s (cleanup_old=%s)", device_id, old_method, new_method, cleanup_old)
        blocklist = blocklist_service.get_blocklist()
        blocked_ips = [entry["ip_address"] for entry in blocklist]

        steps = []

        client = PfSenseClient(
            host=device["hostname"],
            username=device.get("web_username", ""),
            password=device.get("web_password", ""),
        )

        if old_method == "floating_rule" and new_method == "null_route":
            if cleanup_old:
                # Remove floating rules
                try:
                    client.remove_floating_rules(ALIAS_NAME)
                    steps.append({"step": "remove_floating_rules", "success": True, "message": "Floating rules removed."})
                except Exception as e:
                    steps.append({"step": "remove_floating_rules", "success": False, "message": str(e)})

                # Remove alias
                try:
                    client.remove_alias(ALIAS_NAME)
                    steps.append({"step": "remove_alias", "success": True, "message": "Alias removed."})
                except Exception as e:
                    steps.append({"step": "remove_alias", "success": False, "message": str(e)})
            else:
                steps.append({"step": "skip_cleanup", "success": True, "message": "Old floating rules and alias left in place."})

            # Add null routes for all blocked IPs
            if blocked_ips:
                def _switch_to_null():
                    for ip in blocked_ips:
                        try:
                            client.add_null_route(ip)
                        except Exception as e:
                            logger.error("Failed to add null route for %s: %s", ip, e)
                    # Update push statuses
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

                t = threading.Thread(target=_switch_to_null, daemon=True)
                t.start()
                steps.append({"step": "create_null_routes", "success": True, "message": f"Creating {len(blocked_ips)} null route(s) in background."})

        elif old_method == "null_route" and new_method == "floating_rule":
            if cleanup_old and blocked_ips:
                # Remove null routes for all blocked IPs
                for ip in blocked_ips:
                    try:
                        client.remove_null_route(ip)
                    except Exception as e:
                        logger.warning("Could not remove null route for %s: %s", ip, e)
                steps.append({"step": "remove_null_routes", "success": True, "message": f"Removed null routes for {len(blocked_ips)} IP(s)."})
            elif not cleanup_old:
                steps.append({"step": "skip_cleanup", "success": True, "message": "Old null routes left in place."})

            # Create alias + floating rules
            try:
                client.ensure_alias_exists(ALIAS_NAME, blocked_ips)
                steps.append({"step": "create_alias", "success": True, "message": f"Alias created with {len(blocked_ips)} IP(s)."})
            except Exception as e:
                steps.append({"step": "create_alias", "success": False, "message": str(e)})

            try:
                client.create_floating_rule(ALIAS_NAME)
                steps.append({"step": "create_floating_rules", "success": True, "message": "Floating rules created."})
            except Exception as e:
                steps.append({"step": "create_floating_rules", "success": False, "message": str(e)})

            # Update push statuses
            if blocked_ips:
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

        # Update the device's block_method in DB
        with get_db(db_path) as conn:
            conn.execute(
                "UPDATE managed_devices SET block_method = ? WHERE id = ?",
                (new_method, device_id),
            )

        all_ok = all(s["success"] for s in steps)
        return jsonify({
            "success": all_ok,
            "steps": steps,
            "message": f"Switched to {new_method}." if all_ok else "Switch completed with issues.",
        })
    except Exception as e:
        logger.error("Error switching block method for device %s: %s", device_id, e)
        return jsonify({"success": False, "message": f"Switch failed: {e}"}), 500
