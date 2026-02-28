"""Operation status routes for polling async operation results and Operations Log."""

import json

from flask import Blueprint, jsonify, render_template, request

from auth import login_required
from config import Config
from database import get_db
from services.rules_engine import RulesEngine

operations_bp = Blueprint("operations", __name__)


@operations_bp.route("/api/operations/<operation_id>")
@login_required
def get_operation_status(operation_id):
    """Return current status of an operation and its per-device results."""
    db_path = Config.DATABASE_PATH
    engine = RulesEngine(db_path=db_path)

    result = engine.get_operation_status(operation_id)
    if result is None:
        return jsonify({"success": False, "message": "Operation not found."}), 404

    return jsonify({"success": True, **result})


# Status priority for ordering: lower number = higher priority
_STATUS_PRIORITY = {
    "in_progress": 0,
    "pending": 1,
    "failed": 2,
    "completed": 3,
}


@operations_bp.route("/operations")
@login_required
def operations_log():
    """Render the Operations Log page."""
    return render_template("operations.html")


@operations_bp.route("/api/operations")
@login_required
def list_operations():
    """Return operations with optional status filter, ordered by status priority."""
    db_path = Config.DATABASE_PATH
    status_filter = request.args.get("status")

    try:
        with get_db(db_path) as conn:
            if status_filter:
                rows = conn.execute(
                    """SELECT oq.id, oq.operation_id, oq.device_id, oq.action,
                              oq.ip_addresses, oq.status, oq.attempt_count,
                              oq.error_message, oq.created_at, oq.started_at,
                              oq.completed_at,
                              COALESCE(NULLIF(md.friendly_name, ''), md.hostname) AS device_hostname
                       FROM operation_queue oq
                       LEFT JOIN managed_devices md ON oq.device_id = md.id
                       WHERE oq.status = ?
                       ORDER BY oq.created_at DESC""",
                    (status_filter,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT oq.id, oq.operation_id, oq.device_id, oq.action,
                              oq.ip_addresses, oq.status, oq.attempt_count,
                              oq.error_message, oq.created_at, oq.started_at,
                              oq.completed_at,
                              COALESCE(NULLIF(md.friendly_name, ''), md.hostname) AS device_hostname
                       FROM operation_queue oq
                       LEFT JOIN managed_devices md ON oq.device_id = md.id
                       ORDER BY
                           CASE oq.status
                               WHEN 'in_progress' THEN 0
                               WHEN 'pending' THEN 1
                               WHEN 'failed' THEN 2
                               WHEN 'completed' THEN 3
                               WHEN 'cancelled' THEN 4
                               ELSE 5
                           END,
                           oq.created_at DESC"""
                ).fetchall()

            # Build summary counts
            summary_rows = conn.execute(
                """SELECT status, COUNT(*) as cnt
                   FROM operation_queue
                   GROUP BY status"""
            ).fetchall()

        summary = {"pending": 0, "in_progress": 0, "completed": 0, "failed": 0, "cancelled": 0}
        for r in summary_rows:
            if r["status"] in summary:
                summary[r["status"]] = r["cnt"]

        operations = []
        for row in rows:
            try:
                ips = json.loads(row["ip_addresses"]) if row["ip_addresses"] else []
            except (json.JSONDecodeError, TypeError):
                ips = []

            operations.append({
                "id": row["id"],
                "operation_id": row["operation_id"],
                "device_hostname": row["device_hostname"] or "Unknown",
                "device_id": row["device_id"],
                "action": row["action"],
                "ip_addresses": ips,
                "status": row["status"],
                "attempt_count": row["attempt_count"],
                "created_at": row["created_at"],
                "started_at": row["started_at"],
                "completed_at": row["completed_at"],
                "error_message": row["error_message"],
            })

        return jsonify({"operations": operations, "summary": summary})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@operations_bp.route("/api/operations/<int:op_id>/cancel", methods=["POST"])
@login_required
def cancel_operation(op_id):
    """Cancel a pending or in_progress operation."""
    db_path = Config.DATABASE_PATH
    try:
        with get_db(db_path) as conn:
            row = conn.execute(
                "SELECT id, status FROM operation_queue WHERE id = ?", (op_id,)
            ).fetchone()
            if not row:
                return jsonify({"success": False, "message": "Operation not found."}), 404
            if row["status"] not in ("pending", "in_progress"):
                return jsonify({"success": False, "message": f"Cannot cancel operation with status '{row['status']}'."}), 400
            conn.execute(
                "UPDATE operation_queue SET status = 'cancelled', completed_at = CURRENT_TIMESTAMP WHERE id = ?",
                (op_id,),
            )
        return jsonify({"success": True, "message": "Operation cancelled."})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@operations_bp.route("/api/operations/cancel-all", methods=["POST"])
@login_required
def cancel_all_operations():
    """Cancel all pending and in_progress operations."""
    db_path = Config.DATABASE_PATH
    try:
        with get_db(db_path) as conn:
            result = conn.execute(
                "UPDATE operation_queue SET status = 'cancelled', completed_at = CURRENT_TIMESTAMP WHERE status IN ('pending', 'in_progress')"
            )
            count = result.rowcount
        return jsonify({"success": True, "message": f"{count} operation(s) cancelled."})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
