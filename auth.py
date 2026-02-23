"""Authentication module for SOC IP Blocker."""

import functools

from flask import redirect, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


def login_required(f):
    """Decorator that redirects unauthenticated users to the login page."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated_function


def hash_password(password: str) -> str:
    """Hash a password using werkzeug's generate_password_hash with pbkdf2:sha256."""
    return generate_password_hash(password, method="pbkdf2:sha256")


def verify_password(stored_hash: str, password: str) -> bool:
    """Verify a password against a stored werkzeug hash."""
    return check_password_hash(stored_hash, password)
