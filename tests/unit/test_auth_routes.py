"""Unit tests for routes/auth_routes.py — login and logout routes."""

import pytest
import flask

from database import init_db, get_db
from auth import hash_password
from routes.auth_routes import auth_bp


@pytest.fixture
def app(tmp_path):
    """Create a minimal Flask app with auth blueprint and a stub dashboard route."""
    app = flask.Flask(__name__, template_folder="../../templates")
    app.secret_key = "test-secret"
    db_path = str(tmp_path / "test.db")
    app.config["DATABASE_PATH"] = db_path

    # Patch config so database.py uses our temp db
    import config
    original_db_path = config.Config.DATABASE_PATH
    config.Config.DATABASE_PATH = db_path

    init_db(db_path)

    app.register_blueprint(auth_bp)

    # Stub dashboard route so url_for('dashboard.index') resolves
    dashboard_bp = flask.Blueprint("dashboard", __name__)

    @dashboard_bp.route("/dashboard")
    def index():
        return "dashboard"

    app.register_blueprint(dashboard_bp)

    yield app

    config.Config.DATABASE_PATH = original_db_path


@pytest.fixture
def client(app):
    return app.test_client()


class TestLoginGet:
    """Tests for GET /login."""

    def test_returns_200(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200

    def test_renders_login_form(self, client):
        resp = client.get("/login")
        assert b"username" in resp.data
        assert b"password" in resp.data


class TestLoginPost:
    """Tests for POST /login with valid and invalid credentials."""

    def test_valid_credentials_redirects_to_dashboard(self, client):
        resp = client.post("/login", data={"username": "admin", "password": "admin"})
        assert resp.status_code == 302
        assert "/dashboard" in resp.headers["Location"]

    def test_valid_credentials_sets_session(self, client, app):
        with client:
            client.post("/login", data={"username": "admin", "password": "admin"})
            with client.session_transaction() as sess:
                assert sess["user"] == "admin"

    def test_invalid_password_redirects_to_login(self, client):
        resp = client.post("/login", data={"username": "admin", "password": "wrong"})
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_invalid_password_flashes_error(self, client):
        with client:
            client.post("/login", data={"username": "admin", "password": "wrong"})
            resp = client.get("/login")
            assert b"Invalid username or password" in resp.data

    def test_nonexistent_user_redirects_to_login(self, client):
        resp = client.post("/login", data={"username": "nobody", "password": "x"})
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_empty_credentials_rejected(self, client):
        resp = client.post("/login", data={"username": "", "password": ""})
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_no_session_set_on_failure(self, client):
        with client:
            client.post("/login", data={"username": "admin", "password": "wrong"})
            with client.session_transaction() as sess:
                assert "user" not in sess


class TestLogout:
    """Tests for GET /logout."""

    def test_clears_session_and_redirects(self, client):
        with client:
            # Log in first
            client.post("/login", data={"username": "admin", "password": "admin"})
            with client.session_transaction() as sess:
                assert "user" in sess

            # Logout
            resp = client.get("/logout")
            assert resp.status_code == 302
            assert "/login" in resp.headers["Location"]

            with client.session_transaction() as sess:
                assert "user" not in sess

    def test_logout_without_session_still_redirects(self, client):
        resp = client.get("/logout")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]
