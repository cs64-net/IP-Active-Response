"""External API routes authenticated via API key (X-API-Key header).

Provides programmatic access to block/unblock/bulk-add operations
for integration with SIEM, SOAR, and automation tools.
"""

import functools
import hashlib
import logging
import secrets

from flask import Blueprint, jsonify, request

from config import Config
from database import get_db
from services.rules_engine import RulesEngine

logger = logging.getLogger(__name__)

api_bp = Blueprint("external_api", __name__, url_prefix="/api/v1")


def _hash_key(raw_key: str) -> str:
    """SHA-256 hash of the raw API key for storage."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def api_key_required(f):
    """Decorator that validates the X-API-Key header against stored keys."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        raw_key = request.headers.get("X-API-Key", "").strip()
        if not raw_key:
            return jsonify({"success": False, "message": "Missing X-API-Key header."}), 401

        key_hash = _hash_key(raw_key)
        db_path = Config.DATABASE_PATH
        try:
            with get_db(db_path) as conn:
                row = conn.execute(
                    "SELECT id, name, created_by FROM api_keys WHERE key_hash = ? AND is_active = 1",
                    (key_hash,),
                ).fetchone()
                if not row:
                    return jsonify({"success": False, "message": "Invalid or revoked API key."}), 401
                # Update last_used_at
                conn.execute(
                    "UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (row["id"],),
                )
                # Attach identity to request for audit trail
                request.api_key_user = f"api:{row['created_by']}:{row['name']}"
        except Exception as e:
            logger.error("API key validation error: %s", e)
            return jsonify({"success": False, "message": "Authentication error."}), 500

        return f(*args, **kwargs)
    return decorated


# ── Key management (session-authenticated, used by Settings UI) ──────────

from auth import login_required


@api_bp.route("/keys", methods=["GET"])
@login_required
def list_keys():
    """List all API keys (without revealing the full key)."""
    db_path = Config.DATABASE_PATH
    with get_db(db_path) as conn:
        rows = conn.execute(
            "SELECT id, name, key_prefix, created_by, created_at, last_used_at, is_active FROM api_keys ORDER BY created_at DESC"
        ).fetchall()
    keys = [dict(r) for r in rows]
    return jsonify({"success": True, "keys": keys})


@api_bp.route("/keys", methods=["POST"])
@login_required
def create_key():
    """Generate a new API key. Returns the raw key once — it cannot be retrieved again."""
    from flask import session
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"success": False, "message": "Key name is required."}), 400

    raw_key = "soc_" + secrets.token_urlsafe(32)
    key_hash = _hash_key(raw_key)
    key_prefix = raw_key[:8] + "..."
    created_by = session.get("user", "unknown")
    db_path = Config.DATABASE_PATH

    with get_db(db_path) as conn:
        conn.execute(
            "INSERT INTO api_keys (name, key_hash, key_prefix, created_by) VALUES (?, ?, ?, ?)",
            (name, key_hash, key_prefix, created_by),
        )
    return jsonify({"success": True, "key": raw_key, "prefix": key_prefix, "message": "API key created. Copy it now — it won't be shown again."})


@api_bp.route("/keys/<int:key_id>", methods=["DELETE"])
@login_required
def delete_key(key_id):
    """Revoke (delete) an API key."""
    db_path = Config.DATABASE_PATH
    with get_db(db_path) as conn:
        result = conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        if result.rowcount == 0:
            return jsonify({"success": False, "message": "Key not found."}), 404
    return jsonify({"success": True, "message": "API key deleted."})


# ── External API endpoints (API-key authenticated) ──────────────────────

@api_bp.route("/block", methods=["POST"])
@api_key_required
def block_ip():
    """Block a single IP address.

    JSON body: {"ip": "1.2.3.4", "note": "optional reason"}
    """
    data = request.get_json() or {}
    ip = (data.get("ip") or "").strip()
    note = (data.get("note") or "").strip()
    if not ip:
        return jsonify({"success": False, "message": "ip is required."}), 400

    engine = RulesEngine(db_path=Config.DATABASE_PATH)
    try:
        result = engine.process_block([ip], request.api_key_user, note)
        if result["errors"]:
            return jsonify({"success": False, "message": "; ".join(result["errors"])}), 400
        return jsonify({
            "success": True,
            "message": f"IP {ip} blocked.",
            "operation_id": result["operation_id"],
        })
    except Exception as e:
        logger.error("API block error: %s", e)
        return jsonify({"success": False, "message": "Internal error."}), 500


@api_bp.route("/block/bulk", methods=["POST"])
@api_key_required
def block_bulk():
    """Block multiple IPs in one request.

    JSON body: {"ips": ["1.2.3.4", "5.6.7.8"], "note": "optional"}
    """
    data = request.get_json() or {}
    ips = data.get("ips", [])
    note = (data.get("note") or "").strip()
    if not isinstance(ips, list) or not ips:
        return jsonify({"success": False, "message": "ips must be a non-empty list."}), 400

    engine = RulesEngine(db_path=Config.DATABASE_PATH)
    try:
        result = engine.process_block(ips, request.api_key_user, note)
        if result["errors"]:
            return jsonify({
                "success": False,
                "message": "; ".join(result["errors"]),
                "ips_added": result["ips_added"],
                "operation_id": result["operation_id"],
            }), 400
        return jsonify({
            "success": True,
            "message": f"{len(result['ips_added'])} IP(s) blocked.",
            "ips_added": result["ips_added"],
            "operation_id": result["operation_id"],
        })
    except Exception as e:
        logger.error("API bulk block error: %s", e)
        return jsonify({"success": False, "message": "Internal error."}), 500


@api_bp.route("/unblock", methods=["POST"])
@api_key_required
def unblock_ip():
    """Remove an IP from the blocklist.

    JSON body: {"ip": "1.2.3.4"}
    """
    data = request.get_json() or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"success": False, "message": "ip is required."}), 400

    engine = RulesEngine(db_path=Config.DATABASE_PATH)
    try:
        result = engine.process_unblock([ip], request.api_key_user)
        if result["errors"]:
            return jsonify({"success": False, "message": "; ".join(result["errors"])}), 400
        return jsonify({
            "success": True,
            "message": f"IP {ip} removed from blocklist.",
            "operation_id": result["operation_id"],
        })
    except Exception as e:
        logger.error("API unblock error: %s", e)
        return jsonify({"success": False, "message": "Internal error."}), 500
