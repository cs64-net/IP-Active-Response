# Feature: soc-ip-blocker, Property 3: Password hashing is non-reversible and verifiable
"""Property-based tests for password hashing round-trip verification."""

from hypothesis import given, settings, HealthCheck
from hypothesis.strategies import text

from auth import hash_password, verify_password


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(password=text())
def test_password_hash_is_non_reversible_and_verifiable(password: str):
    """**Validates: Requirements 1.5**

    For any plaintext password, the stored hash should not equal the plaintext,
    and verify_password(hash, plaintext) should return True (round-trip verification).
    """
    stored_hash = hash_password(password)

    # Hash must differ from plaintext (non-reversible)
    assert stored_hash != password, "Hash should never equal the plaintext password"

    # Round-trip verification must succeed
    assert verify_password(stored_hash, password) is True, (
        "verify_password must return True for the original plaintext"
    )

# Feature: soc-ip-blocker, Property 2: Invalid credentials are always rejected

import os
import tempfile

import config as config_module
from hypothesis import assume
from hypothesis.strategies import text as st_text

from app import create_app
from config import Config
from database import init_db


def _make_test_app():
    """Create a Flask test app with a fresh temporary database."""
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    # Patch Config.DATABASE_PATH so get_db() in routes uses the temp DB
    config_module.Config.DATABASE_PATH = db_path

    init_db(db_path)

    class TestConfig(Config):
        TESTING = True
        DATABASE_PATH = db_path
        SECRET_KEY = "test-secret"

    app = create_app(config_class=TestConfig)
    return app, db_path


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    username=st_text(min_size=1),
    password=st_text(min_size=1),
)
def test_invalid_credentials_are_always_rejected(username: str, password: str):
    """**Validates: Requirements 1.3**

    For any username/password pair that does not match a stored user,
    submitting those credentials should result in authentication failure
    and the user remaining on the login page.
    """
    # Ensure the generated credentials do NOT match the default admin user
    assume(not (username == Config.DEFAULT_ADMIN_USER and password == Config.DEFAULT_ADMIN_PASSWORD))

    app, db_path = _make_test_app()
    try:
        with app.test_client() as client:
            response = client.post(
                "/login",
                data={"username": username, "password": password},
                follow_redirects=False,
            )

            # Should redirect back to login page (302)
            assert response.status_code == 302, (
                f"Expected 302 redirect, got {response.status_code}"
            )
            assert "/login" in response.headers.get("Location", ""), (
                "Expected redirect to /login on invalid credentials"
            )

            # Session should NOT contain a user
            with client.session_transaction() as sess:
                assert "user" not in sess, (
                    f"Session should not contain 'user' for invalid credentials "
                    f"(username={username!r}, password={password!r})"
                )
    finally:
        os.unlink(db_path)

