"""Honeypot routes for OpenCanary honeypot integration.

Provides UI routes for managing honeypot instances, viewing alerts,
blocked IPs, and configuring honeypot settings. Webhook and API
endpoints are added in subsequent tasks.
"""

import json
import logging
from typing import Optional

import os

from flask import Blueprint, flash, jsonify, redirect, render_template, request, send_file, url_for

from auth import login_required
from config import Config
from routes.api_routes import api_key_required
from services.alert_forwarder import AlertForwarder
from services.blocklist_service import BlocklistService
from services.honeypot_manager import HoneypotManager
from services.rules_engine import _write_audit_log

logger = logging.getLogger(__name__)

honeypot_bp = Blueprint("honeypot", __name__)

# Module-level references set during app initialization
_honeypot_manager: Optional[HoneypotManager] = None
_alert_forwarder: Optional[AlertForwarder] = None


def init_honeypot_routes(honeypot_manager: HoneypotManager, alert_forwarder: Optional[AlertForwarder] = None):
    """Initialize module-level HoneypotManager and AlertForwarder references for use by routes."""
    global _honeypot_manager, _alert_forwarder
    _honeypot_manager = honeypot_manager
    _alert_forwarder = alert_forwarder


def _get_honeypot_manager() -> HoneypotManager:
    """Return the module-level HoneypotManager or create a new one."""
    if _honeypot_manager is not None:
        return _honeypot_manager
    return HoneypotManager(db_path=Config.DATABASE_PATH)

def _validate_honeypot_token() -> tuple:
    """Validate X-Honeypot-Token header and return (instance, None) or (None, error_response).

    Extracts the X-Honeypot-Token header from the current request, validates it
    against registered honeypot instances, and returns the matching instance dict
    on success or an error response tuple on failure.

    Returns:
        (instance_dict, None) on success, or
        (None, (json_response, status_code)) on failure.
    """
    token = request.headers.get("X-Honeypot-Token", "").strip()
    if not token:
        return None, (jsonify({"success": False, "message": "Missing X-Honeypot-Token header."}), 401)

    manager = _get_honeypot_manager()
    instance = manager.get_instance_by_token(token)
    if instance is None:
        return None, (jsonify({"success": False, "message": "Invalid or revoked honeypot token."}), 401)

    return instance, None


# ── Default bundle path ──
OFFLINE_BUNDLE_PATH = os.path.join("offline_bundle", "opencanary-offline.tar.gz")


# ── Offline Endpoints ──


@honeypot_bp.route("/api/v1/honeypot/offline/bundle", methods=["GET"])
def offline_bundle_download():
    """Serve the offline bundle archive.

    Auth: X-Honeypot-Token header.
    Returns: The .tar.gz file via send_file, or 401/404/500.
    """
    try:
        instance, error_response = _validate_honeypot_token()
        if error_response is not None:
            return error_response

        if not os.path.isfile(OFFLINE_BUNDLE_PATH):
            return jsonify({
                "success": False,
                "message": "Offline bundle not built. Run: flask build-offline-bundle",
            }), 404

        instance_name = instance.get("name", "unknown")
        requesting_ip = request.remote_addr

        logger.info(
            "Offline bundle downloaded by instance '%s' from %s",
            instance_name,
            requesting_ip,
        )

        _write_audit_log(
            Config.DATABASE_PATH,
            event_type="honeypot_offline_deploy",
            action=f"Offline bundle downloaded by instance '{instance_name}'",
            target_ips=[requesting_ip],
            details={
                "instance_name": instance_name,
                "requesting_ip": requesting_ip,
            },
        )

        return send_file(
            OFFLINE_BUNDLE_PATH,
            mimetype="application/gzip",
            as_attachment=True,
            download_name="opencanary-offline.tar.gz",
        )
    except Exception as e:
        logger.error("Unhandled error in offline bundle download: %s", e, exc_info=True)
        return jsonify({"success": False, "message": "Internal server error."}), 500

@honeypot_bp.route("/api/v1/honeypot/offline/config", methods=["GET"])
def offline_config_download():
    """Generate and serve instance-specific opencanary.conf.

    Auth: X-Honeypot-Token header.
    Returns: JSON config file, or 401/500.
    """
    try:
        instance, error_response = _validate_honeypot_token()
        if error_response is not None:
            return error_response

        raw_token = request.headers.get("X-Honeypot-Token", "").strip()
        soc_url = request.url_root.rstrip("/")

        honeypot_manager = _get_honeypot_manager()
        config = honeypot_manager.generate_instance_config(instance, raw_token, soc_url)

        instance_name = instance.get("name", "unknown")
        requesting_ip = request.remote_addr

        logger.info(
            "Offline config downloaded by instance '%s' from %s",
            instance_name,
            requesting_ip,
        )

        _write_audit_log(
            Config.DATABASE_PATH,
            event_type="honeypot_offline_config",
            action=f"Offline config downloaded by instance '{instance_name}'",
            target_ips=[requesting_ip],
            details={
                "instance_name": instance_name,
                "requesting_ip": requesting_ip,
            },
        )

        return jsonify(config), 200

    except Exception as e:
        logger.error("Unhandled error in offline config download: %s", e, exc_info=True)
        return jsonify({"success": False, "message": "Internal server error."}), 500


@honeypot_bp.route("/api/v1/honeypot/offline/build", methods=["POST"])
@login_required
def offline_bundle_build():
    """Trigger an offline bundle build from the UI.

    Auth: Session login (admin).
    Returns: JSON with success status and bundle info.
    """
    try:
        from scripts.build_offline_bundle import build_offline_bundle

        result_path = build_offline_bundle()
        manager = _get_honeypot_manager()
        bundle_info = manager.get_offline_bundle_info()

        logger.info("Offline bundle built successfully: %s", result_path)
        return jsonify({
            "success": True,
            "message": "Bundle built successfully.",
            "bundle_info": bundle_info,
        })
    except FileNotFoundError as e:
        logger.error("Bundle build failed - source not found: %s", e)
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        logger.error("Bundle build failed: %s", e, exc_info=True)
        return jsonify({"success": False, "message": f"Build failed: {e}"}), 500



# ── OpenCanary Log Type to Service Name Mapping ──

LOGTYPE_SERVICE_MAP = {
    # Boot / system
    1000: "boot",
    1001: "system",
    1002: "debug",
    1003: "error",
    1004: "ping",
    1005: "config",
    1006: "example",
    # FTP
    2000: "ftp",
    2001: "ftp",
    # HTTP
    3000: "http",
    3001: "http",
    3002: "http",
    3003: "http",
    # SSH
    4000: "ssh",
    4001: "ssh",
    4002: "ssh",
    # SMB / Portscan
    5000: "smb",
    5001: "portscan",
    5002: "portscan",
    5003: "portscan",
    5004: "portscan",
    5005: "portscan",
    # Telnet
    6001: "telnet",
    6002: "telnet",
    # HTTP Proxy
    7001: "httpproxy",
    # MySQL
    8001: "mysql",
    # MSSQL
    9001: "mssql",
    9002: "mssql",
    9003: "mysql",
    # TFTP
    10001: "tftp",
    # NTP
    11001: "ntp",
    # VNC
    12001: "vnc",
    # SNMP
    13001: "snmp",
    # RDP
    14001: "rdp",
    # SIP
    15001: "sip",
    # Git
    16001: "git",
    # Redis
    17001: "redis",
    # TCP Banner
    18001: "tcp_banner",
    18002: "tcp_banner",
    18003: "tcp_banner",
    18004: "tcp_banner",
    18005: "tcp_banner",
    # LLMNR
    19001: "llmnr",
    # User modules
    99000: "user_module",
    99001: "user_module",
    99002: "user_module",
    99003: "user_module",
    99004: "user_module",
    99005: "user_module",
    99006: "user_module",
    99007: "user_module",
    99008: "user_module",
    99009: "user_module",
}

# Human-readable descriptions for each logtype
LOGTYPE_DESCRIPTION = {
    1000: "Service boot",
    1001: "System message",
    1002: "Debug message",
    1003: "Error",
    1004: "Ping/heartbeat",
    1005: "Config saved",
    1006: "Example event",
    2000: "FTP login attempt",
    2001: "FTP auth initiated",
    3000: "HTTP GET request",
    3001: "HTTP POST login attempt",
    3002: "HTTP unimplemented method",
    3003: "HTTP redirect",
    4000: "SSH new connection",
    4001: "SSH remote version sent",
    4002: "SSH login attempt",
    5000: "SMB file open",
    5001: "Port SYN scan",
    5002: "Nmap OS detection",
    5003: "Nmap NULL scan",
    5004: "Nmap XMAS scan",
    5005: "Nmap FIN scan",
    6001: "Telnet login attempt",
    6002: "Telnet connection made",
    7001: "HTTP Proxy login attempt",
    8001: "MySQL login attempt",
    9001: "MSSQL login (SQL auth)",
    9002: "MSSQL login (Windows auth)",
    9003: "MySQL connection made",
    10001: "TFTP request",
    11001: "NTP monlist request",
    12001: "VNC connection",
    13001: "SNMP command",
    14001: "RDP connection",
    15001: "SIP request",
    16001: "Git clone request",
    17001: "Redis command",
    18001: "TCP banner connection",
    18002: "TCP banner keep-alive connection",
    18003: "TCP banner keep-alive secret",
    18004: "TCP banner keep-alive data",
    18005: "TCP banner data received",
    19001: "LLMNR query response",
}


# ── UI Routes ──


def _render_honeypot_page(**extra_context):
    """Shared helper to render the honeypot page with all panel data."""
    manager = _get_honeypot_manager()

    try:
        instances = manager.get_all_instances()
    except Exception as e:
        logger.error("Error fetching honeypot instances: %s", e)
        instances = []

    try:
        page = request.args.get("page", 1, type=int)
        search = request.args.get("search", "", type=str).strip() or None
        alerts_data = manager.get_alerts(page=page, search=search)
    except Exception as e:
        logger.error("Error fetching honeypot alerts: %s", e)
        alerts_data = {"alerts": [], "total": 0, "page": 1, "pages": 1}

    try:
        blocked_ips = manager.get_blocked_ips()
    except Exception as e:
        logger.error("Error fetching honeypot blocked IPs: %s", e)
        blocked_ips = []

    try:
        stats = manager.get_stats()
    except Exception as e:
        logger.error("Error fetching honeypot stats: %s", e)
        stats = {"total_instances": 0, "active_instances": 0, "alerts_24h": 0, "blocked_ips": 0}

    try:
        settings = manager.get_settings()
    except Exception as e:
        logger.error("Error fetching honeypot settings: %s", e)
        settings = {"honeypot_timeout": 86400, "honeypot_staleness_threshold": 3600}

    try:
        bundle_info = manager.get_offline_bundle_info()
    except Exception as e:
        logger.error("Error fetching offline bundle info: %s", e)
        bundle_info = {"available": False, "size_bytes": None, "last_built": None, "path": ""}

    ctx = dict(
        instances=instances,
        alerts=alerts_data["alerts"],
        alerts_total=alerts_data["total"],
        alerts_page=alerts_data["page"],
        alerts_pages=alerts_data["pages"],
        blocked_ips=blocked_ips,
        stats=stats,
        settings=settings,
        offline_bundle_info=bundle_info,
        search=search or "",
        wizard_data=None,
    )
    ctx.update(extra_context)
    return render_template("honeypot.html", **ctx)


@honeypot_bp.route("/honeypot")
@login_required
def index():
    """Render the Honey Pot section page with all panels."""
    return _render_honeypot_page()


@honeypot_bp.route("/honeypot/instances/add", methods=["POST"])
@login_required
def add_instance():
    """Register a new honeypot instance and show setup wizard with generated config."""
    name = request.form.get("name", "").strip()
    ip_address = request.form.get("ip_address", "").strip()
    services_raw = request.form.get("services", "").strip()

    if not name or not ip_address:
        flash("Instance name and IP address are required.", "error")
        return redirect(url_for("honeypot.index"))

    # Parse comma-separated services list
    services = [s.strip() for s in services_raw.split(",") if s.strip()] if services_raw else []

    manager = _get_honeypot_manager()
    try:
        result = manager.register_instance(name, ip_address, services)
        raw_token = result["token"]
        soc_url = request.host_url.rstrip("/")
        try:
            b_info = manager.get_offline_bundle_info()
            b_avail = b_info.get("available", False) if b_info else False
        except Exception:
            b_avail = False
        wizard_data = json.dumps({
            "name": name,
            "ip_address": ip_address,
            "token": raw_token,
            "services": services,
            "soc_url": soc_url,
            "bundle_available": b_avail,
        })
        return _render_honeypot_page(wizard_data=wizard_data)
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        logger.error("Error registering honeypot instance '%s': %s", name, e)
        flash("An unexpected error occurred while registering the instance.", "error")

    return redirect(url_for("honeypot.index"))


@honeypot_bp.route("/honeypot/instances/<int:instance_id>/delete", methods=["POST"])
@login_required
def delete_instance(instance_id):
    """Delete a honeypot instance."""
    manager = _get_honeypot_manager()
    try:
        manager.delete_instance(instance_id)
        flash("Honeypot instance deleted.")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        logger.error("Error deleting honeypot instance %d: %s", instance_id, e)
        flash("An unexpected error occurred while deleting the instance.", "error")

    return redirect(url_for("honeypot.index"))


@honeypot_bp.route("/honeypot/settings", methods=["POST"])
@login_required
def update_settings():
    """Update honeypot timeout, staleness threshold, and SIEM settings."""
    timeout_raw = request.form.get("honeypot_timeout", "").strip()
    staleness_raw = request.form.get("honeypot_staleness_threshold", "").strip()

    manager = _get_honeypot_manager()

    kwargs = {}
    if timeout_raw:
        try:
            kwargs["timeout"] = int(timeout_raw)
        except (ValueError, TypeError):
            flash("Timeout must be a valid integer.", "error")
            return redirect(url_for("honeypot.index"))

    if staleness_raw:
        try:
            kwargs["staleness_threshold"] = int(staleness_raw)
        except (ValueError, TypeError):
            flash("Staleness threshold must be a valid integer.", "error")
            return redirect(url_for("honeypot.index"))

    # ── SIEM fields ──
    kwargs["elastic_enabled"] = 1 if request.form.get("elastic_enabled") else 0
    kwargs["elastic_host"] = request.form.get("elastic_host", "").strip()
    kwargs["elastic_index"] = request.form.get("elastic_index", "").strip()
    kwargs["elastic_api_key"] = request.form.get("elastic_api_key", "").strip()
    kwargs["elastic_tls_verify"] = 1 if request.form.get("elastic_tls_verify") else 0
    kwargs["syslog_enabled"] = 1 if request.form.get("syslog_enabled") else 0
    kwargs["syslog_host"] = request.form.get("syslog_host", "").strip()
    syslog_port_raw = request.form.get("syslog_port", "").strip()
    if syslog_port_raw:
        try:
            kwargs["syslog_port"] = int(syslog_port_raw)
        except (ValueError, TypeError):
            flash("Syslog port must be a valid integer.", "error")
            return redirect(url_for("honeypot.index"))
    kwargs["syslog_protocol"] = request.form.get("syslog_protocol", "udp").strip()
    kwargs["syslog_facility"] = request.form.get("syslog_facility", "local0").strip()

    try:
        manager.update_settings(**kwargs)
        flash("Honeypot settings updated successfully.")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        logger.error("Error updating honeypot settings: %s", e)
        flash("An unexpected error occurred while updating settings.", "error")

    return redirect(url_for("honeypot.index"))


@honeypot_bp.route("/honeypot/test-elasticsearch", methods=["POST"])
@login_required
def test_elasticsearch():
    """Test Elasticsearch connectivity with the provided settings."""
    try:
        settings = request.get_json(silent=True)
        if not settings:
            return jsonify({"success": False, "message": "No JSON body provided."}), 400
        if _alert_forwarder is not None:
            result = _alert_forwarder.test_elasticsearch(settings)
        else:
            result = AlertForwarder.test_elasticsearch(settings)
        return jsonify(result)
    except Exception as e:
        logger.error("Error testing Elasticsearch connection: %s", e)
        return jsonify({"success": False, "message": str(e)}), 500


@honeypot_bp.route("/honeypot/test-syslog", methods=["POST"])
@login_required
def test_syslog():
    """Test Syslog connectivity with the provided settings."""
    try:
        settings = request.get_json(silent=True)
        if not settings:
            return jsonify({"success": False, "message": "No JSON body provided."}), 400
        if _alert_forwarder is not None:
            result = _alert_forwarder.test_syslog(settings)
        else:
            result = AlertForwarder.test_syslog(settings)
        return jsonify(result)
    except Exception as e:
        logger.error("Error testing Syslog connection: %s", e)
        return jsonify({"success": False, "message": str(e)}), 500


@honeypot_bp.route("/honeypot/unblock/<path:ip_address>", methods=["POST"])
@login_required
def unblock_ip(ip_address):
    """Remove a honeypot-blocked IP from the blocklist and honeypot_block_entries."""
    manager = _get_honeypot_manager()
    try:
        manager.unblock_ip(ip_address)
        flash(f"IP {ip_address} has been unblocked.")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        logger.error("Error unblocking honeypot IP %s: %s", ip_address, e)
        flash("An unexpected error occurred while unblocking the IP.", "error")
    return redirect(url_for("honeypot.index"))


# ── Webhook Endpoint ──


def _extract_alert(data: dict) -> Optional[dict]:
    """Try to extract the flat OpenCanary alert dict from a wrapper.

    OpenCanary's WebhookHandler may wrap the alert JSON string inside
    a "message", "event", or "data" key.  This helper unwraps it.
    Returns the dict containing src_host, or None if not found.
    """
    # Direct: top-level dict already has src_host
    if "src_host" in data:
        return data

    # Try common wrapper keys
    for key in ("message", "event", "data"):
        val = data.get(key)
        if val is None:
            continue
        if isinstance(val, dict) and "src_host" in val:
            return val
        if isinstance(val, str):
            try:
                parsed = json.loads(val)
                if isinstance(parsed, dict) and "src_host" in parsed:
                    return parsed
            except (json.JSONDecodeError, TypeError):
                continue

    # Last resort: scan all string values
    for val in data.values():
        if isinstance(val, str) and "src_host" in val:
            try:
                parsed = json.loads(val)
                if isinstance(parsed, dict) and "src_host" in parsed:
                    return parsed
            except (json.JSONDecodeError, TypeError):
                continue

    return None


@honeypot_bp.route("/api/v1/honeypot/alert", methods=["POST"])
def receive_alert():
    """Webhook endpoint for OpenCanary alerts.

    Auth: X-Honeypot-Token header (per-instance token, not the global API key).
    Parses the OpenCanary JSON payload, validates the attacker IP, and delegates
    to HoneypotManager.process_alert for blocking/enrichment.

    Returns:
        200 on success or protected-range skip,
        401 on missing/invalid token,
        400 on bad payload or invalid IP,
        500 on internal error.
    """
    try:
        # 1. Validate X-Honeypot-Token header
        instance, error_response = _validate_honeypot_token()
        if error_response is not None:
            return error_response

        manager = _get_honeypot_manager()

        # 2. Parse payload
        # OpenCanary's WebhookHandler sends data in different formats depending
        # on config.  Default (no "data" key, no Content-Type header) sends
        # form-encoded: message=<url-encoded-json-string>.
        # With Content-Type: application/json it sends JSON: {"message": "<json>"}.
        # With a custom "data" template it may send the alert fields directly.
        alert_data = None

        # Strategy A: JSON body (Content-Type: application/json)
        data = request.get_json(silent=True)
        if data is not None:
            logger.info("Honeypot webhook JSON payload: %s", json.dumps(data)[:500])
            alert_data = _extract_alert(data)

        # Strategy B: Form-encoded body (default WebhookHandler behaviour)
        if alert_data is None and request.form:
            logger.info("Honeypot webhook form payload keys: %s", list(request.form.keys()))
            # The default sends a single "message" field with the JSON string
            for key in ("message", "event", "data"):
                raw = request.form.get(key, "")
                if raw:
                    try:
                        parsed = json.loads(raw)
                        if isinstance(parsed, dict):
                            alert_data = parsed
                            logger.info("Honeypot webhook: extracted alert from form field '%s'", key)
                            break
                    except (json.JSONDecodeError, TypeError):
                        continue

        # Strategy C: Raw body fallback
        if alert_data is None:
            raw_body = request.get_data(as_text=True)
            logger.info("Honeypot webhook raw body: %s", raw_body[:500] if raw_body else "(empty)")
            if raw_body:
                try:
                    parsed = json.loads(raw_body)
                    if isinstance(parsed, dict):
                        alert_data = _extract_alert(parsed)
                except (json.JSONDecodeError, TypeError):
                    pass

        if alert_data is None:
            return jsonify({"success": False, "message": "Could not parse alert payload."}), 400

        # Handle boot/heartbeat events (logtype 1000-1006) — these confirm
        # the instance is alive without needing to block anything.
        logtype = alert_data.get("logtype")
        if logtype is not None:
            try:
                logtype = int(logtype)
            except (ValueError, TypeError):
                logtype = None

        # Handle boot event (logtype 1000-1001) — this confirms the instance is alive
        # without needing to block anything. OpenCanary sends logtype 1000 on startup
        # and logtype 1001 for general messages including heartbeats.
        if logtype in (1000, 1001):
            manager.touch_instance(instance["id"])
            logger.info("Honeypot boot/heartbeat event (logtype %s) from instance '%s'", logtype, instance.get("name"))
            return jsonify({"success": True, "action": "heartbeat", "message": "Instance registered as active."}), 200

        src_host = alert_data.get("src_host")
        if not src_host:
            return jsonify({"success": False, "message": "Missing required field: src_host."}), 400

        attacker_ip = str(src_host).strip()

        # Map logtype to service name (already parsed above)
        service_name = LOGTYPE_SERVICE_MAP.get(logtype, "unknown") if logtype is not None else "unknown"
        if service_name == "unknown" and logtype is not None:
            service_name = f"logtype_{logtype}"

        timestamp = alert_data.get("local_time_adjusted", "")

        # 4. Validate attacker IP
        blocklist_svc = BlocklistService(db_path=Config.DATABASE_PATH)
        is_valid, error_msg = blocklist_svc.validate_ip(attacker_ip)
        if not is_valid:
            return jsonify({"success": False, "message": f"Invalid attacker IP: {error_msg}."}), 400

        # 5. Delegate to HoneypotManager.process_alert
        result = manager.process_alert(
            instance_id=instance["id"],
            attacker_ip=attacker_ip,
            service_name=service_name,
            timestamp=timestamp,
            raw_payload=json.dumps(alert_data, default=str),
        )

        if result["action"] == "skipped_protected":
            return jsonify({
                "success": True,
                "action": "skipped_protected",
                "message": "IP in protected range.",
            }), 200

        return jsonify({
            "success": True,
            "action": result["action"],
        }), 200

    except Exception as e:
        logger.error("Unhandled error in honeypot alert webhook: %s", e, exc_info=True)
        return jsonify({"success": False, "message": "Internal server error."}), 500


# ── API Endpoints (API-key authenticated) ──


@honeypot_bp.route("/api/v1/honeypot/instances", methods=["GET"])
@api_key_required
def api_instances():
    """Return all registered honeypot instances with status."""
    try:
        manager = _get_honeypot_manager()
        instances = manager.get_all_instances()
        return jsonify({"success": True, "instances": instances})
    except Exception as e:
        logger.error("API error fetching honeypot instances: %s", e)
        return jsonify({"success": False, "message": "Internal server error."}), 500


@honeypot_bp.route("/api/v1/honeypot/alerts", methods=["GET"])
@api_key_required
def api_alerts():
    """Return recent honeypot alerts with pagination support."""
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 50, type=int)
        search = request.args.get("search", "", type=str).strip() or None
        manager = _get_honeypot_manager()
        result = manager.get_alerts(page=page, per_page=per_page, search=search)
        return jsonify({"success": True, **result})
    except Exception as e:
        logger.error("API error fetching honeypot alerts: %s", e)
        return jsonify({"success": False, "message": "Internal server error."}), 500


@honeypot_bp.route("/api/v1/honeypot/blocked", methods=["GET"])
@api_key_required
def api_blocked():
    """Return all honeypot-blocked IPs with instance/service/threat info."""
    try:
        manager = _get_honeypot_manager()
        blocked = manager.get_blocked_ips()
        return jsonify({"success": True, "blocked": blocked})
    except Exception as e:
        logger.error("API error fetching honeypot blocked IPs: %s", e)
        return jsonify({"success": False, "message": "Internal server error."}), 500


@honeypot_bp.route("/api/v1/honeypot/stats", methods=["GET"])
@api_key_required
def api_stats():
    """Return honeypot summary statistics."""
    try:
        manager = _get_honeypot_manager()
        stats = manager.get_stats()
        return jsonify({"success": True, "stats": stats})
    except Exception as e:
        logger.error("API error fetching honeypot stats: %s", e)
        return jsonify({"success": False, "message": "Internal server error."}), 500
