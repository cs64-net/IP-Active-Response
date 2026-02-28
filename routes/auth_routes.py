"""Authentication routes for SOC IP Blocker."""

from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for

from auth import login_required, verify_password
from database import get_db
from rate_limiter import RateLimiter

auth_bp = Blueprint("auth", __name__)

# 5 login attempts per 60-second window per IP — no lockout, just throttle
_login_limiter = RateLimiter(max_attempts=5, window_seconds=60)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Handle login page display (GET) and credential validation (POST)."""
    if request.method == "POST":
        client_ip = request.remote_addr or "unknown"
        is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"

        # Rate limit check — no lockout, just slow down
        if _login_limiter.is_rate_limited(client_ip):
            retry = _login_limiter.retry_after(client_ip)
            if is_ajax:
                return jsonify({
                    "success": False,
                    "message": f"Too many login attempts. Try again in {retry}s.",
                    "retry_after": retry,
                }), 429
            flash("Too many login attempts. Please wait a moment.")
            return redirect(url_for("auth.login"))

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        with get_db() as conn:
            user = conn.execute(
                "SELECT username, password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if user and verify_password(user["password_hash"], password):
            session["user"] = user["username"]
            if is_ajax:
                return jsonify({"success": True, "redirect": url_for("dashboard.index")})
            return redirect(url_for("dashboard.index"))
        else:
            _login_limiter.record_attempt(client_ip)
            if is_ajax:
                remaining = _login_limiter.remaining(client_ip)
                return jsonify({
                    "success": False,
                    "message": "Invalid username or password.",
                    "remaining_attempts": remaining,
                }), 401
            flash("Invalid username or password.")
            return redirect(url_for("auth.login"))

    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    """Clear session and redirect to login page."""
    session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/users", methods=["GET"])
@login_required
def list_users():
    """Return JSON list of all users (without password hashes)."""
    with get_db() as conn:
        rows = conn.execute("SELECT id, username FROM users ORDER BY id").fetchall()
    return jsonify({"users": [dict(r) for r in rows]})


@auth_bp.route("/users/add", methods=["POST"])
@login_required
def add_user():
    """Add a new user. Expects JSON {username, password}."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Invalid request."}), 400

    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required."}), 400

    if len(username) < 3:
        return jsonify({"success": False, "message": "Username must be at least 3 characters."}), 400

    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters."}), 400

    from auth import hash_password
    try:
        with get_db() as conn:
            existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                return jsonify({"success": False, "message": f"User '{username}' already exists."}), 400
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hash_password(password)),
            )
        return jsonify({"success": True, "message": f"User '{username}' created."})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error creating user: {e}"}), 500


@auth_bp.route("/users/change-password", methods=["POST"])
@login_required
def change_password():
    """Change password for current user or specified user. Expects JSON {current_password, new_password} or {username, new_password} for admin."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Invalid request."}), 400

    target_username = (data.get("username") or "").strip()
    current_password = (data.get("current_password") or "").strip()
    new_password = (data.get("new_password") or "").strip()

    if not new_password or len(new_password) < 6:
        return jsonify({"success": False, "message": "New password must be at least 6 characters."}), 400

    current_user = session.get("user", "")

    from auth import hash_password, verify_password as verify_pw

    # If changing own password, require current password
    if not target_username or target_username == current_user:
        if not current_password:
            return jsonify({"success": False, "message": "Current password is required."}), 400
        with get_db() as conn:
            user = conn.execute("SELECT password_hash FROM users WHERE username = ?", (current_user,)).fetchone()
            if not user or not verify_pw(user["password_hash"], current_password):
                return jsonify({"success": False, "message": "Current password is incorrect."}), 400
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (hash_password(new_password), current_user),
            )
        return jsonify({"success": True, "message": "Password changed successfully."})
    else:
        # Admin changing another user's password - no current password needed
        with get_db() as conn:
            user = conn.execute("SELECT id FROM users WHERE username = ?", (target_username,)).fetchone()
            if not user:
                return jsonify({"success": False, "message": f"User '{target_username}' not found."}), 404
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (hash_password(new_password), target_username),
            )
        return jsonify({"success": True, "message": f"Password for '{target_username}' changed."})


@auth_bp.route("/users/remove", methods=["POST"])
@login_required
def remove_user():
    """Remove a user. Expects JSON {username}. Cannot remove yourself."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Invalid request."}), 400

    username = (data.get("username") or "").strip()
    current_user = session.get("user", "")

    if not username:
        return jsonify({"success": False, "message": "Username is required."}), 400

    if username == current_user:
        return jsonify({"success": False, "message": "You cannot remove your own account."}), 400

    try:
        with get_db() as conn:
            cursor = conn.execute("DELETE FROM users WHERE username = ?", (username,))
            if cursor.rowcount == 0:
                return jsonify({"success": False, "message": f"User '{username}' not found."}), 404
        return jsonify({"success": True, "message": f"User '{username}' removed."})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error removing user: {e}"}), 500
