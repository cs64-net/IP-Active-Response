"""Unit tests for auth.py — login_required decorator, hash_password, and verify_password."""

import flask
import pytest

from auth import hash_password, login_required, verify_password


@pytest.fixture
def app():
    """Create a minimal Flask app for testing."""
    app = flask.Flask(__name__)
    app.secret_key = "test-secret"

    # Register a dummy blueprint so url_for('auth.login') resolves
    bp = flask.Blueprint("auth", __name__)

    @bp.route("/login")
    def login():
        return "login page"

    app.register_blueprint(bp)

    # A protected route for testing the decorator
    @app.route("/protected")
    @login_required
    def protected():
        return "secret content"

    return app


class TestHashPassword:
    """Tests for hash_password function."""

    def test_returns_string(self):
        result = hash_password("mypassword")
        assert isinstance(result, str)

    def test_hash_differs_from_plaintext(self):
        password = "mypassword"
        hashed = hash_password(password)
        assert hashed != password

    def test_uses_pbkdf2_sha256(self):
        hashed = hash_password("test")
        assert hashed.startswith("pbkdf2:sha256:")

    def test_different_calls_produce_different_hashes(self):
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2  # salted hashes should differ


class TestVerifyPassword:
    """Tests for verify_password function."""

    def test_correct_password_returns_true(self):
        hashed = hash_password("correct")
        assert verify_password(hashed, "correct") is True

    def test_wrong_password_returns_false(self):
        hashed = hash_password("correct")
        assert verify_password(hashed, "wrong") is False

    def test_empty_password_hashes_and_verifies(self):
        hashed = hash_password("")
        assert verify_password(hashed, "") is True
        assert verify_password(hashed, "notempty") is False


class TestLoginRequired:
    """Tests for login_required decorator."""

    def test_redirects_when_no_session(self, app):
        with app.test_client() as client:
            resp = client.get("/protected")
            assert resp.status_code == 302
            assert "/login" in resp.headers["Location"]

    def test_allows_access_with_session(self, app):
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["user"] = "admin"
            resp = client.get("/protected")
            assert resp.status_code == 200
            assert resp.data == b"secret content"

    def test_preserves_function_name(self):
        @login_required
        def my_view():
            pass
        assert my_view.__name__ == "my_view"

    def test_preserves_docstring(self):
        @login_required
        def my_view():
            """My docstring."""
            pass
        assert my_view.__doc__ == "My docstring."
