"""Unit tests for routes/dashboard_routes.py — dashboard and status refresh routes."""

import pytest
from unittest.mock import patch

from flask import Flask

from routes.dashboard_routes import dashboard_bp


def create_test_app():
    """Create a minimal Flask app for testing dashboard routes."""
    app = Flask(__name__, template_folder="../../templates")
    app.secret_key = "test-secret"
    app.config["TESTING"] = True

    from routes.auth_routes import auth_bp
    from routes.blocklist_routes import blocklist_bp
    from routes.settings_routes import settings_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(blocklist_bp)
    app.register_blueprint(settings_bp)
    return app


@pytest.fixture
def app():
    return create_test_app()


@pytest.fixture
def client(app):
    return app.test_client()


def login(client):
    """Set session user to simulate authentication."""
    with client.session_transaction() as sess:
        sess["user"] = "admin"


class TestRootRedirect:
    """Tests for GET /."""

    def test_root_redirects_to_dashboard(self, client):
        resp = client.get("/")
        assert resp.status_code == 302
        assert "/dashboard" in resp.headers["Location"]


class TestDashboardIndex:
    """Tests for GET /dashboard."""

    def test_requires_login(self, client):
        resp = client.get("/dashboard")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    @patch("routes.dashboard_routes.Config")
    @patch("routes.dashboard_routes.DeviceManager")
    @patch("routes.dashboard_routes.BlocklistService")
    def test_renders_dashboard(self, MockBLS, MockDM, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        MockBLS.return_value.get_blocklist.return_value = [
            {"id": 1, "ip_address": "10.0.0.1", "added_by": "admin",
             "added_at": "2024-01-01", "note": "", "push_statuses": []},
        ]
        MockDM.return_value.get_all_devices.return_value = [
            {"id": 1, "hostname": "fw1", "device_type": "pfsense", "status": "online"},
            {"id": 2, "hostname": "lx1", "device_type": "linux", "status": "offline"},
        ]

        login(client)
        resp = client.get("/dashboard")

        assert resp.status_code == 200
        assert b"Blocked IPs" in resp.data
        assert b"10.0.0.1" in resp.data
        assert b"fw1" in resp.data

    @patch("routes.dashboard_routes.Config")
    @patch("routes.dashboard_routes.DeviceManager")
    @patch("routes.dashboard_routes.BlocklistService")
    def test_empty_data(self, MockBLS, MockDM, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        MockBLS.return_value.get_blocklist.return_value = []
        MockDM.return_value.get_all_devices.return_value = []

        login(client)
        resp = client.get("/dashboard")

        assert resp.status_code == 200
        assert b"Blocked IPs" in resp.data
        assert b"No blocked IPs" in resp.data

    @patch("routes.dashboard_routes.Config")
    @patch("routes.dashboard_routes.DeviceManager")
    @patch("routes.dashboard_routes.BlocklistService")
    def test_counts_multiple_statuses(self, MockBLS, MockDM, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        MockBLS.return_value.get_blocklist.return_value = [
            {"id": i, "ip_address": f"10.0.0.{i}", "added_by": "admin",
             "added_at": "2024-01-01", "note": "", "push_statuses": []}
            for i in range(1, 4)
        ]
        MockDM.return_value.get_all_devices.return_value = [
            {"id": 1, "hostname": "fw1", "device_type": "pfsense", "status": "online"},
            {"id": 2, "hostname": "fw2", "device_type": "pfsense", "status": "online"},
            {"id": 3, "hostname": "lx1", "device_type": "linux", "status": "offline"},
            {"id": 4, "hostname": "lx2", "device_type": "linux", "status": "unknown"},
        ]

        login(client)
        resp = client.get("/dashboard")

        assert resp.status_code == 200
        assert b"10.0.0.1" in resp.data
        assert b"fw1" in resp.data
        assert b"lx1" in resp.data

    @patch("routes.dashboard_routes.Config")
    @patch("routes.dashboard_routes.DeviceManager")
    @patch("routes.dashboard_routes.BlocklistService")
    def test_service_error_shows_empty(self, MockBLS, MockDM, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        MockBLS.return_value.get_blocklist.side_effect = RuntimeError("db error")

        login(client)
        resp = client.get("/dashboard")

        assert resp.status_code == 200
        assert b"Blocked IPs" in resp.data


class TestDashboardRefresh:
    """Tests for POST /dashboard/refresh."""

    def test_requires_login(self, client):
        resp = client.post("/dashboard/refresh")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    @patch("routes.dashboard_routes.Config")
    @patch("routes.dashboard_routes.StatusMonitor")
    def test_refresh_success(self, MockMonitor, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        MockMonitor.return_value.check_all_devices.return_value = {
            1: "online", 2: "offline",
        }

        login(client)
        resp = client.post("/dashboard/refresh")

        assert resp.status_code == 302
        assert "/dashboard" in resp.headers["Location"]
        MockMonitor.return_value.check_all_devices.assert_called_once()

    @patch("routes.dashboard_routes.Config")
    @patch("routes.dashboard_routes.StatusMonitor")
    def test_refresh_error(self, MockMonitor, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        MockMonitor.return_value.check_all_devices.side_effect = RuntimeError("fail")

        login(client)
        resp = client.post("/dashboard/refresh")

        assert resp.status_code == 302
        assert "/dashboard" in resp.headers["Location"]

    @patch("routes.dashboard_routes.Config")
    @patch("routes.dashboard_routes.StatusMonitor")
    def test_refresh_flash_message(self, MockMonitor, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        MockMonitor.return_value.check_all_devices.return_value = {
            1: "online", 2: "online", 3: "offline",
        }

        login(client)
        resp = client.post("/dashboard/refresh", follow_redirects=False)

        assert resp.status_code == 302
        with client.session_transaction() as sess:
            flashes = sess.get("_flashes", [])
            messages = [msg for _, msg in flashes]
            assert any("2 online" in m and "1 offline" in m for m in messages)
