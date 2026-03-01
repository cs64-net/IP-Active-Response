"""Device management routes for adding, editing, removing, and testing devices."""

import logging

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for

from auth import login_required
from config import Config
from services.device_manager import DeviceManager
from services.rules_engine import RulesEngine
from services.status_monitor import StatusMonitor

logger = logging.getLogger(__name__)

devices_bp = Blueprint("devices", __name__)


@devices_bp.route("/devices")
@login_required
def devices_page():
    """Render the dedicated devices management page."""
    db_path = Config.DATABASE_PATH
    device_manager = DeviceManager(db_path=db_path)
    devices = device_manager.get_all_devices()
    return render_template("devices.html", devices=devices)


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
        elif device_type == "cisco_ios":
            hostname = request.form.get("hostname", "").strip()
            port = int(request.form.get("ssh_port", 22))
            username = request.form.get("ssh_username", "").strip()
            password = request.form.get("ssh_password", "").strip()
            enable_password = request.form.get("enable_password", "").strip()
            group_name = request.form.get("group_name", "SOC_BLOCKLIST").strip()
            friendly_name = request.form.get("friendly_name", "").strip()
            device = dm.add_cisco_ios(hostname, port, username, password, enable_password, acl_name=group_name, friendly_name=friendly_name)
            msg = f"Cisco IOS device {hostname} added successfully."
        elif device_type == "cisco_asa":
            hostname = request.form.get("hostname", "").strip()
            port = int(request.form.get("ssh_port", 22))
            username = request.form.get("ssh_username", "").strip()
            password = request.form.get("ssh_password", "").strip()
            enable_password = request.form.get("enable_password", "").strip()
            group_name = request.form.get("group_name", "SOC_BLOCKLIST").strip()
            friendly_name = request.form.get("friendly_name", "").strip()
            device = dm.add_cisco_asa(hostname, port, username, password, enable_password, object_group_name=group_name, friendly_name=friendly_name)
            msg = f"Cisco ASA device {hostname} added successfully."
        elif device_type == "fortinet":
            hostname = request.form.get("hostname", "").strip()
            connection_protocol = request.form.get("connection_protocol", "ssh").strip()
            group_name = request.form.get("group_name", "SOC_BLOCKLIST").strip()
            friendly_name = request.form.get("friendly_name", "").strip()
            if connection_protocol == "https":
                api_key = request.form.get("api_key", "").strip()
                api_port = int(request.form.get("api_port", 443))
                device = dm.add_fortinet(hostname, 22, "", "", address_group_name=group_name, friendly_name=friendly_name, connection_protocol="https", api_key=api_key)
            else:
                port = int(request.form.get("ssh_port", 22))
                username = request.form.get("ssh_username", "").strip()
                password = request.form.get("ssh_password", "").strip()
                device = dm.add_fortinet(hostname, port, username, password, address_group_name=group_name, friendly_name=friendly_name, connection_protocol="ssh")
            msg = f"Fortinet device {hostname} added successfully."
        elif device_type == "palo_alto":
            hostname = request.form.get("hostname", "").strip()
            connection_protocol = request.form.get("connection_protocol", "ssh").strip()
            group_name = request.form.get("group_name", "SOC_BLOCKLIST").strip()
            friendly_name = request.form.get("friendly_name", "").strip()
            if connection_protocol == "https":
                api_key = request.form.get("api_key", "").strip()
                api_port = int(request.form.get("api_port", 443))
                device = dm.add_palo_alto(hostname, 22, "", "", address_group_name=group_name, friendly_name=friendly_name, connection_protocol="https", api_key=api_key)
            else:
                port = int(request.form.get("ssh_port", 22))
                username = request.form.get("ssh_username", "").strip()
                password = request.form.get("ssh_password", "").strip()
                device = dm.add_palo_alto(hostname, port, username, password, address_group_name=group_name, friendly_name=friendly_name, connection_protocol="ssh")
            msg = f"Palo Alto device {hostname} added successfully."
        elif device_type == "unifi":
            hostname = request.form.get("hostname", "").strip()
            api_port = int(request.form.get("api_port", 443))
            username = request.form.get("ssh_username", "").strip()
            password = request.form.get("ssh_password", "").strip()
            group_name = request.form.get("group_name", "SOC_BLOCKLIST").strip()
            friendly_name = request.form.get("friendly_name", "").strip()
            device = dm.add_unifi(hostname, api_port, username, password, network_list_name=group_name, friendly_name=friendly_name)
            msg = f"UniFi device {hostname} added successfully."
        elif device_type == "juniper_srx":
            hostname = request.form.get("hostname", "").strip()
            port = int(request.form.get("ssh_port", 22))
            username = request.form.get("ssh_username", "").strip()
            password = request.form.get("ssh_password", "").strip()
            group_name = request.form.get("group_name", "SOC_BLOCKLIST").strip()
            block_method = request.form.get("block_method", "address_group").strip()
            friendly_name = request.form.get("friendly_name", "").strip()
            device = dm.add_juniper_srx(hostname, port, username, password, address_group_name=group_name, block_method=block_method, friendly_name=friendly_name)
            msg = f"Juniper SRX device {hostname} added successfully."
        elif device_type == "juniper_mx":
            hostname = request.form.get("hostname", "").strip()
            port = int(request.form.get("ssh_port", 22))
            username = request.form.get("ssh_username", "").strip()
            password = request.form.get("ssh_password", "").strip()
            group_name = request.form.get("group_name", "SOC_BLOCKLIST").strip()
            block_method = request.form.get("block_method", "address_group").strip()
            friendly_name = request.form.get("friendly_name", "").strip()
            device = dm.add_juniper_mx(hostname, port, username, password, address_group_name=group_name, block_method=block_method, friendly_name=friendly_name)
            msg = f"Juniper MX device {hostname} added successfully."
        elif device_type == "checkpoint":
            hostname = request.form.get("hostname", "").strip()
            api_port = int(request.form.get("api_port", 443))
            username = request.form.get("ssh_username", "").strip()
            password = request.form.get("ssh_password", "").strip()
            domain = request.form.get("domain", "").strip()
            group_name = request.form.get("group_name", "SOC_BLOCKLIST").strip()
            friendly_name = request.form.get("friendly_name", "").strip()
            device = dm.add_checkpoint(hostname, api_port, username, password, domain=domain, object_group_name=group_name, friendly_name=friendly_name)
            msg = f"Check Point device {hostname} added successfully."
        elif device_type == "aws_waf":
            hostname = request.form.get("hostname", "").strip()
            access_key = request.form.get("access_key", "").strip()
            secret_key = request.form.get("secret_key", "").strip()
            region = request.form.get("region", "").strip()
            ip_set_name = request.form.get("ip_set_name", "").strip()
            ip_set_scope = request.form.get("ip_set_scope", "REGIONAL").strip()
            friendly_name = request.form.get("friendly_name", "").strip()
            ipv4_ip_set_name = request.form.get("ipv4_ip_set_name", "").strip()
            ipv6_ip_set_name = request.form.get("ipv6_ip_set_name", "").strip()
            device = dm.add_aws_waf(hostname, access_key, secret_key, region, ip_set_name, ip_set_scope, friendly_name, ipv4_ip_set_name=ipv4_ip_set_name, ipv6_ip_set_name=ipv6_ip_set_name)
            msg = f"AWS WAF device {hostname} added successfully."
        elif device_type == "azure_nsg":
            hostname = request.form.get("hostname", "").strip()
            tenant_id = request.form.get("tenant_id", "").strip()
            client_id = request.form.get("client_id", "").strip()
            client_secret = request.form.get("client_secret", "").strip()
            subscription_id = request.form.get("subscription_id", "").strip()
            resource_group = request.form.get("resource_group", "").strip()
            nsg_name = request.form.get("nsg_name", "").strip()
            friendly_name = request.form.get("friendly_name", "").strip()
            device = dm.add_azure_nsg(hostname, tenant_id, client_id, client_secret, subscription_id, resource_group, nsg_name, friendly_name)
            msg = f"Azure NSG device {hostname} added successfully."
        elif device_type == "gcp_firewall":
            hostname = request.form.get("hostname", "").strip()
            service_account_json = request.form.get("service_account_json", "").strip()
            project_id = request.form.get("project_id", "").strip()
            network_name = request.form.get("network_name", "").strip()
            friendly_name = request.form.get("friendly_name", "").strip()
            device = dm.add_gcp_firewall(hostname, service_account_json, project_id, network_name, friendly_name)
            msg = f"GCP Firewall device {hostname} added successfully."
        elif device_type == "oci_nsg":
            hostname = request.form.get("hostname", "").strip()
            tenancy_ocid = request.form.get("tenancy_ocid", "").strip()
            user_ocid = request.form.get("user_ocid", "").strip()
            api_key_pem = request.form.get("api_key_pem", "").strip()
            fingerprint = request.form.get("fingerprint", "").strip()
            region = request.form.get("region", "").strip()
            nsg_ocid = request.form.get("nsg_ocid", "").strip()
            friendly_name = request.form.get("friendly_name", "").strip()
            device = dm.add_oci_nsg(hostname, tenancy_ocid, user_ocid, api_key_pem, fingerprint, region, nsg_ocid, friendly_name)
            msg = f"OCI NSG device {hostname} added successfully."
        else:
            if wants_json:
                return jsonify({"success": False, "message": "Invalid device type."}), 400
            flash("Invalid device type.", "error")
            return redirect(url_for("devices.devices_page"))

        # Trigger full blocklist sync for the new device
        engine = RulesEngine(db_path=db_path)
        operation_id = engine.onboard_device(device["id"])

        if wants_json:
            return jsonify({"success": True, "message": msg, "device_id": device["id"], "operation_id": operation_id})
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

    return redirect(url_for("devices.devices_page"))


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
        elif device_type == "cisco_ios":
            hostname = (data.get("hostname") or "").strip()
            port = int(data.get("ssh_port") or 22)
            username = (data.get("ssh_username") or "").strip()
            password = (data.get("ssh_password") or "").strip()
            enable_password = (data.get("enable_password") or "").strip()
            group_name = (data.get("group_name") or "SOC_BLOCKLIST").strip()
            friendly_name = (data.get("friendly_name") or "").strip()
            device = dm.add_cisco_ios(hostname, port, username, password, enable_password, acl_name=group_name, friendly_name=friendly_name)
        elif device_type == "cisco_asa":
            hostname = (data.get("hostname") or "").strip()
            port = int(data.get("ssh_port") or 22)
            username = (data.get("ssh_username") or "").strip()
            password = (data.get("ssh_password") or "").strip()
            enable_password = (data.get("enable_password") or "").strip()
            group_name = (data.get("group_name") or "SOC_BLOCKLIST").strip()
            friendly_name = (data.get("friendly_name") or "").strip()
            device = dm.add_cisco_asa(hostname, port, username, password, enable_password, object_group_name=group_name, friendly_name=friendly_name)
        elif device_type == "fortinet":
            hostname = (data.get("hostname") or "").strip()
            connection_protocol = (data.get("connection_protocol") or "ssh").strip()
            group_name = (data.get("group_name") or "SOC_BLOCKLIST").strip()
            friendly_name = (data.get("friendly_name") or "").strip()
            if connection_protocol == "https":
                api_key = (data.get("api_key") or "").strip()
                api_port = int(data.get("api_port") or 443)
                device = dm.add_fortinet(hostname, 22, "", "", address_group_name=group_name, friendly_name=friendly_name, connection_protocol="https", api_key=api_key)
            else:
                port = int(data.get("ssh_port") or 22)
                username = (data.get("ssh_username") or "").strip()
                password = (data.get("ssh_password") or "").strip()
                device = dm.add_fortinet(hostname, port, username, password, address_group_name=group_name, friendly_name=friendly_name, connection_protocol="ssh")
        elif device_type == "palo_alto":
            hostname = (data.get("hostname") or "").strip()
            connection_protocol = (data.get("connection_protocol") or "ssh").strip()
            group_name = (data.get("group_name") or "SOC_BLOCKLIST").strip()
            friendly_name = (data.get("friendly_name") or "").strip()
            if connection_protocol == "https":
                api_key = (data.get("api_key") or "").strip()
                api_port = int(data.get("api_port") or 443)
                device = dm.add_palo_alto(hostname, 22, "", "", address_group_name=group_name, friendly_name=friendly_name, connection_protocol="https", api_key=api_key)
            else:
                port = int(data.get("ssh_port") or 22)
                username = (data.get("ssh_username") or "").strip()
                password = (data.get("ssh_password") or "").strip()
                device = dm.add_palo_alto(hostname, port, username, password, address_group_name=group_name, friendly_name=friendly_name, connection_protocol="ssh")
        elif device_type == "unifi":
            hostname = (data.get("hostname") or "").strip()
            api_port = int(data.get("api_port") or 443)
            username = (data.get("ssh_username") or "").strip()
            password = (data.get("ssh_password") or "").strip()
            group_name = (data.get("group_name") or "SOC_BLOCKLIST").strip()
            friendly_name = (data.get("friendly_name") or "").strip()
            device = dm.add_unifi(hostname, api_port, username, password, network_list_name=group_name, friendly_name=friendly_name)
        elif device_type == "juniper_srx":
            hostname = (data.get("hostname") or "").strip()
            port = int(data.get("ssh_port") or 22)
            username = (data.get("ssh_username") or "").strip()
            password = (data.get("ssh_password") or "").strip()
            group_name = (data.get("group_name") or "SOC_BLOCKLIST").strip()
            block_method = (data.get("block_method") or "address_group").strip()
            friendly_name = (data.get("friendly_name") or "").strip()
            device = dm.add_juniper_srx(hostname, port, username, password, address_group_name=group_name, block_method=block_method, friendly_name=friendly_name)
        elif device_type == "juniper_mx":
            hostname = (data.get("hostname") or "").strip()
            port = int(data.get("ssh_port") or 22)
            username = (data.get("ssh_username") or "").strip()
            password = (data.get("ssh_password") or "").strip()
            group_name = (data.get("group_name") or "SOC_BLOCKLIST").strip()
            block_method = (data.get("block_method") or "address_group").strip()
            friendly_name = (data.get("friendly_name") or "").strip()
            device = dm.add_juniper_mx(hostname, port, username, password, address_group_name=group_name, block_method=block_method, friendly_name=friendly_name)
        elif device_type == "checkpoint":
            hostname = (data.get("hostname") or "").strip()
            api_port = int(data.get("api_port") or 443)
            username = (data.get("ssh_username") or "").strip()
            password = (data.get("ssh_password") or "").strip()
            domain = (data.get("domain") or "").strip()
            group_name = (data.get("group_name") or "SOC_BLOCKLIST").strip()
            friendly_name = (data.get("friendly_name") or "").strip()
            device = dm.add_checkpoint(hostname, api_port, username, password, domain=domain, object_group_name=group_name, friendly_name=friendly_name)
        elif device_type == "aws_waf":
            hostname = (data.get("hostname") or "").strip()
            access_key = (data.get("access_key") or "").strip()
            secret_key = (data.get("secret_key") or "").strip()
            region = (data.get("region") or "").strip()
            ip_set_name = (data.get("ip_set_name") or "").strip()
            ip_set_scope = (data.get("ip_set_scope") or "REGIONAL").strip()
            friendly_name = (data.get("friendly_name") or "").strip()
            ipv4_ip_set_name = (data.get("ipv4_ip_set_name") or "").strip()
            ipv6_ip_set_name = (data.get("ipv6_ip_set_name") or "").strip()
            device = dm.add_aws_waf(hostname, access_key, secret_key, region, ip_set_name, ip_set_scope, friendly_name, ipv4_ip_set_name=ipv4_ip_set_name, ipv6_ip_set_name=ipv6_ip_set_name)
        elif device_type == "azure_nsg":
            hostname = (data.get("hostname") or "").strip()
            tenant_id = (data.get("tenant_id") or "").strip()
            client_id = (data.get("client_id") or "").strip()
            client_secret = (data.get("client_secret") or "").strip()
            subscription_id = (data.get("subscription_id") or "").strip()
            resource_group = (data.get("resource_group") or "").strip()
            nsg_name = (data.get("nsg_name") or "").strip()
            friendly_name = (data.get("friendly_name") or "").strip()
            device = dm.add_azure_nsg(hostname, tenant_id, client_id, client_secret, subscription_id, resource_group, nsg_name, friendly_name)
        elif device_type == "gcp_firewall":
            hostname = (data.get("hostname") or "").strip()
            service_account_json = (data.get("service_account_json") or "").strip()
            project_id = (data.get("project_id") or "").strip()
            network_name = (data.get("network_name") or "").strip()
            friendly_name = (data.get("friendly_name") or "").strip()
            device = dm.add_gcp_firewall(hostname, service_account_json, project_id, network_name, friendly_name)
        elif device_type == "oci_nsg":
            hostname = (data.get("hostname") or "").strip()
            tenancy_ocid = (data.get("tenancy_ocid") or "").strip()
            user_ocid = (data.get("user_ocid") or "").strip()
            api_key_pem = (data.get("api_key_pem") or "").strip()
            fingerprint = (data.get("fingerprint") or "").strip()
            region = (data.get("region") or "").strip()
            nsg_ocid = (data.get("nsg_ocid") or "").strip()
            friendly_name = (data.get("friendly_name") or "").strip()
            device = dm.add_oci_nsg(hostname, tenancy_ocid, user_ocid, api_key_pem, fingerprint, region, nsg_ocid, friendly_name)
        else:
            return jsonify({"success": False, "message": "Invalid device type."}), 400

        # Trigger full blocklist sync for the new device
        engine = RulesEngine(db_path=db_path)
        operation_id = engine.onboard_device(device["id"])

        return jsonify({"success": True, "message": f"Device {hostname} added.", "device_id": device["id"], "operation_id": operation_id})
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
                "ssh_username", "ssh_password", "ssh_key_path", "friendly_name",
                "ssh_key", "sudo_password", "enable_password", "group_name",
                "cloud_credentials", "cloud_region", "cloud_resource_id",
                "connection_protocol", "ipv4_group_name", "ipv6_group_name"):
        val = request.form.get(key, "").strip()
        if val:
            fields[key] = val

    port_val = request.form.get("ssh_port", "").strip()
    if port_val:
        fields["ssh_port"] = int(port_val)

    api_port_val = request.form.get("api_port", "").strip()
    if api_port_val:
        fields["api_port"] = int(api_port_val)

    try:
        dm.update_device(device_id, **fields)
        flash("Device updated successfully.")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        logger.error("Error editing device %s: %s", device_id, e)
        flash("An unexpected error occurred while updating the device.", "error")

    return redirect(url_for("devices.devices_page"))




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
            return redirect(url_for("devices.devices_page"))

        # Decommission via RulesEngine (handles cleanup and deletion)
        engine = RulesEngine(db_path=db_path)
        operation_id = engine.decommission_device(device_id, cleanup=cleanup)

        msg = "Device removed successfully."
        if cleanup:
            msg = "Device removal with cleanup initiated."

        if is_json:
            return jsonify({"success": True, "message": msg, "operation_id": operation_id})
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

    return redirect(url_for("devices.devices_page"))


@devices_bp.route("/devices/test/<int:device_id>", methods=["POST"])
@login_required
def test_device(device_id):
    """Test connectivity to a device and return JSON result.

    For new device types (cisco_ios, cisco_asa, fortinet, palo_alto, unifi),
    instantiates the correct client via CLIENT_REGISTRY and calls check_health().
    For legacy types, falls back to StatusMonitor.check_device().
    """
    db_path = Config.DATABASE_PATH
    dm = DeviceManager(db_path=db_path)

    try:
        devices = dm.get_all_devices()
        device = next((d for d in devices if d["id"] == device_id), None)
        if device is None:
            return jsonify({"success": False, "message": f"Device {device_id} not found."}), 404

        device_type = device.get("device_type", "")
        client_types = {"cisco_ios", "cisco_asa", "fortinet", "palo_alto", "unifi",
                        "aws_waf", "azure_nsg", "gcp_firewall", "oci_nsg",
                        "juniper_srx", "juniper_mx", "checkpoint"}

        if device_type in client_types:
            from services.push_orchestrator import CLIENT_REGISTRY
            factory = CLIENT_REGISTRY.get(device_type)
            if factory is None:
                return jsonify({"success": False, "message": f"No client registered for type '{device_type}'."}), 400
            client = factory(device)
            healthy = client.check_health()
            status = "online" if healthy else "offline"
        else:
            monitor = StatusMonitor(db_path=db_path)
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

@devices_bp.route("/devices/sync/<int:device_id>", methods=["POST"])
@login_required
def sync_device(device_id):
    """Trigger blocklist sync for a single device and return JSON result."""
    db_path = Config.DATABASE_PATH
    dm = DeviceManager(db_path=db_path)

    try:
        devices = dm.get_all_devices()
        device = next((d for d in devices if d["id"] == device_id), None)
        if device is None:
            return jsonify({"success": False, "message": "Device not found"}), 404

        engine = RulesEngine(db_path=db_path)
        engine.onboard_device(device_id)

        return jsonify({"success": True, "message": "Blocklist synced successfully"})
    except Exception as e:
        logger.error("Error syncing device %s: %s", device_id, e)
        return jsonify({"success": False, "message": f"Sync failed: {e}"}), 500


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

        elif device_type in ("cisco_ios", "cisco_asa", "unifi", "juniper_srx", "juniper_mx"):
            from services.push_orchestrator import CLIENT_REGISTRY
            # Build a device dict from the submitted data
            dev = {
                "hostname": hostname,
                "ssh_port": int(data.get("ssh_port") or 22),
                "ssh_username": (data.get("ssh_username") or "").strip(),
                "ssh_password": (data.get("ssh_password") or "").strip(),
                "enable_password": (data.get("enable_password") or "").strip(),
                "group_name": (data.get("group_name") or "SOC_BLOCKLIST").strip(),
                "api_port": int(data.get("api_port") or 443),
            }
            factory = CLIENT_REGISTRY.get(device_type)
            if factory is None:
                return jsonify({"success": False, "message": f"No client for type '{device_type}'."}), 400
            try:
                client = factory(dev)
                healthy = client.check_health()
                if healthy:
                    return jsonify({"success": True, "message": "Connection successful — credentials are valid."})
                else:
                    return jsonify({"success": False, "message": "Connection failed — check credentials and connectivity."}), 400
            except Exception as e:
                return jsonify({"success": False, "message": f"Connection failed: {e}"}), 400

        elif device_type in ("fortinet", "palo_alto"):
            from services.push_orchestrator import CLIENT_REGISTRY
            connection_protocol = (data.get("connection_protocol") or "ssh").strip()
            dev = {
                "hostname": hostname,
                "device_type": device_type,
                "ssh_port": int(data.get("ssh_port") or 22),
                "ssh_username": (data.get("ssh_username") or "").strip(),
                "ssh_password": (data.get("ssh_password") or "").strip(),
                "group_name": (data.get("group_name") or "SOC_BLOCKLIST").strip(),
                "api_port": int(data.get("api_port") or 443),
                "connection_protocol": connection_protocol,
                "cloud_credentials": "",
            }
            if connection_protocol == "https":
                import json as _json
                dev["cloud_credentials"] = _json.dumps({"api_key": (data.get("api_key") or "").strip()})
            factory = CLIENT_REGISTRY.get(device_type)
            if factory is None:
                return jsonify({"success": False, "message": f"No client for type '{device_type}'."}), 400
            try:
                client = factory(dev)
                healthy = client.check_health()
                if healthy:
                    return jsonify({"success": True, "message": "Connection successful — credentials are valid."})
                else:
                    return jsonify({"success": False, "message": "Connection failed — check credentials and connectivity."}), 400
            except Exception as e:
                return jsonify({"success": False, "message": f"Connection failed: {e}"}), 400

        elif device_type == "checkpoint":
            from services.push_orchestrator import CLIENT_REGISTRY
            import json as _json
            dev = {
                "hostname": hostname,
                "device_type": "checkpoint",
                "api_port": int(data.get("api_port") or 443),
                "ssh_username": (data.get("ssh_username") or "").strip(),
                "ssh_password": (data.get("ssh_password") or "").strip(),
                "group_name": (data.get("group_name") or "SOC_BLOCKLIST").strip(),
                "cloud_credentials": _json.dumps({"domain": (data.get("domain") or "").strip()}),
            }
            factory = CLIENT_REGISTRY.get("checkpoint")
            if factory is None:
                return jsonify({"success": False, "message": "No client for type 'checkpoint'."}), 400
            try:
                client = factory(dev)
                healthy = client.check_health()
                if healthy:
                    return jsonify({"success": True, "message": "Connection successful — credentials are valid."})
                else:
                    return jsonify({"success": False, "message": "Connection failed — check credentials and connectivity."}), 400
            except Exception as e:
                return jsonify({"success": False, "message": f"Connection failed: {e}"}), 400

        elif device_type in ("aws_waf", "azure_nsg", "gcp_firewall", "oci_nsg"):
            import json as _json
            from services.push_orchestrator import CLIENT_REGISTRY

            # Build a device dict with cloud_credentials JSON matching what
            # the CLIENT_REGISTRY factory functions expect.
            cloud_creds = {}
            cloud_region = ""
            cloud_resource_id = ""

            if device_type == "aws_waf":
                cloud_creds = {
                    "access_key": (data.get("access_key") or "").strip(),
                    "secret_key": (data.get("secret_key") or "").strip(),
                    "ip_set_scope": (data.get("ip_set_scope") or "REGIONAL").strip(),
                }
                cloud_region = (data.get("region") or "").strip()
                cloud_resource_id = (data.get("ip_set_name") or "").strip()
            elif device_type == "azure_nsg":
                cloud_creds = {
                    "tenant_id": (data.get("tenant_id") or "").strip(),
                    "client_id": (data.get("client_id") or "").strip(),
                    "client_secret": (data.get("client_secret") or "").strip(),
                    "subscription_id": (data.get("subscription_id") or "").strip(),
                    "resource_group": (data.get("resource_group") or "").strip(),
                }
                cloud_resource_id = (data.get("nsg_name") or "").strip()
            elif device_type == "gcp_firewall":
                cloud_creds = {
                    "service_account_json": (data.get("service_account_json") or "").strip(),
                    "network_name": (data.get("network_name") or "").strip(),
                }
                cloud_resource_id = (data.get("project_id") or "").strip()
            elif device_type == "oci_nsg":
                cloud_creds = {
                    "tenancy_ocid": (data.get("tenancy_ocid") or "").strip(),
                    "user_ocid": (data.get("user_ocid") or "").strip(),
                    "api_key_pem": (data.get("api_key_pem") or "").strip(),
                    "fingerprint": (data.get("fingerprint") or "").strip(),
                }
                cloud_region = (data.get("region") or "").strip()
                cloud_resource_id = (data.get("nsg_ocid") or "").strip()

            dev = {
                "hostname": hostname,
                "device_type": device_type,
                "cloud_credentials": _json.dumps(cloud_creds),
                "cloud_region": cloud_region,
                "cloud_resource_id": cloud_resource_id,
            }

            factory = CLIENT_REGISTRY.get(device_type)
            if factory is None:
                return jsonify({"success": False, "message": f"No client for type '{device_type}'."}), 400
            try:
                client = factory(dev)
                healthy = client.check_health()
                if healthy:
                    return jsonify({"success": True, "message": "Connection successful — credentials are valid."})
                else:
                    return jsonify({"success": False, "message": "Connection failed — check credentials and connectivity."}), 400
            except Exception as e:
                return jsonify({"success": False, "message": f"Connection failed: {e}"}), 400

        else:
            return jsonify({"success": False, "message": "Invalid device type."}), 400
    except Exception as e:
        logger.error("Error validating credentials: %s", e)
        return jsonify({"success": False, "message": f"Validation error: {e}"}), 500

