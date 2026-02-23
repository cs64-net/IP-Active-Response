"""Unit tests for routes/settings_routes.py — settings, update, and floating rule routes."""

import pytest
from unittest.mock import patch, MagicMock

from flask import Flask

from routes.settings_routes import settings_bp


def create_test_app():
    """Create a minimal Flask app for testing settings routes."""
    app = Flask(__name__, template_folder="../../templates")
    app.secret_key = "test-secret"
    app.config["TESTING"] = True

    from routes.auth_routes import auth_bp
    from routes.device_routes import devices_bp
    from routes.dashboard_routes import dashboard_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(dashboard_bp)
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


class TestSettingsIndex:
    """Tests for GET /settings."""

    def test_requires_login(self, client):
        resp = client.get("/settings")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    @patch("routes.settings_routes.get_db")
    @patch("routes.settings_routes.Config")
    @patch("routes.settings_routes.DeviceManager")
    def test_renders_settings(self, MockDM, MockConfig, mock_get_db, client):
        MockConfig.DATABASE_PATH = ":memory:"
        MockDM.return_value.get_all_devices.return_value = [
            {"id": 1, "hostname": "fw1", "device_type": "pfsense"},
        ]
        mock_conn = MagicMock()
        mock_row = {"monitor_interval": 300, "default_block_method": "null_route"}
        mock_conn.execute.return_value.fetchone.return_value = mock_row
        mock_get_db.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_get_db.return_value.__exit__ = MagicMock(return_value=False)

        login(client)
        resp = client.get("/settings")

        assert resp.status_code == 200
        assert b"Settings" in resp.data

    @patch("routes.settings_routes.get_db")
    @patch("routes.settings_routes.Config")
    @patch("routes.settings_routes.DeviceManager")
    def test_device_error_shows_empty(self, MockDM, MockConfig, mock_get_db, client):
        MockConfig.DATABASE_PATH = ":memory:"
        MockDM.return_value.get_all_devices.side_effect = RuntimeError("db error")
        mock_conn = MagicMock()
        mock_row = {"monitor_interval": 300, "default_block_method": "null_route"}
        mock_conn.execute.return_value.fetchone.return_value = mock_row
        mock_get_db.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_get_db.return_value.__exit__ = MagicMock(return_value=False)

        login(client)
        resp = client.get("/settings")

        assert resp.status_code == 200

    @patch("routes.settings_routes.get_db")
    @patch("routes.settings_routes.Config")
    @patch("routes.settings_routes.DeviceManager")
    def test_settings_error_uses_defaults(self, MockDM, MockConfig, mock_get_db, client):
        MockConfig.DATABASE_PATH = ":memory:"
        MockDM.return_value.get_all_devices.return_value = []
        mock_get_db.return_value.__enter__ = MagicMock(side_effect=RuntimeError("db error"))
        mock_get_db.return_value.__exit__ = MagicMock(return_value=False)

        login(client)
        resp = client.get("/settings")

        assert resp.status_code == 200


class TestSettingsUpdate:
    """Tests for POST /settings/update."""

    def test_requires_login(self, client):
        resp = client.post("/settings/update", data={
            "monitor_interval": "300",
            "default_block_method": "null_route",
        })
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    @patch("routes.settings_routes.get_db")
    @patch("routes.settings_routes.Config")
    def test_valid_update(self, MockConfig, mock_get_db, client):
        MockConfig.DATABASE_PATH = ":memory:"
        mock_conn = MagicMock()
        mock_get_db.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_get_db.return_value.__exit__ = MagicMock(return_value=False)

        login(client)
        resp = client.post("/settings/update", data={
            "monitor_interval": "600",
            "default_block_method": "floating_rule",
        })

        assert resp.status_code == 302
        assert "/settings" in resp.headers["Location"]
        mock_conn.execute.assert_called_once_with(
            "UPDATE app_settings SET monitor_interval = ?, default_block_method = ? WHERE id = 1",
            (600, "floating_rule"),
        )

    @patch("routes.settings_routes.Config")
    def test_invalid_interval_not_integer(self, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"

        login(client)
        resp = client.post("/settings/update", data={
            "monitor_interval": "abc",
            "default_block_method": "null_route",
        })

        assert resp.status_code == 302
        assert "/settings" in resp.headers["Location"]
        with client.session_transaction() as sess:
            flashes = sess.get("_flashes", [])
            messages = [msg for _, msg in flashes]
            assert any("positive integer" in m for m in messages)

    @patch("routes.settings_routes.Config")
    def test_invalid_interval_zero(self, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"

        login(client)
        resp = client.post("/settings/update", data={
            "monitor_interval": "0",
            "default_block_method": "null_route",
        })

        assert resp.status_code == 302
        with client.session_transaction() as sess:
            flashes = sess.get("_flashes", [])
            messages = [msg for _, msg in flashes]
            assert any("positive integer" in m for m in messages)

    @patch("routes.settings_routes.Config")
    def test_invalid_interval_negative(self, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"

        login(client)
        resp = client.post("/settings/update", data={
            "monitor_interval": "-10",
            "default_block_method": "null_route",
        })

        assert resp.status_code == 302
        with client.session_transaction() as sess:
            flashes = sess.get("_flashes", [])
            messages = [msg for _, msg in flashes]
            assert any("positive integer" in m for m in messages)

    @patch("routes.settings_routes.Config")
    def test_invalid_block_method(self, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"

        login(client)
        resp = client.post("/settings/update", data={
            "monitor_interval": "300",
            "default_block_method": "invalid_method",
        })

        assert resp.status_code == 302
        with client.session_transaction() as sess:
            flashes = sess.get("_flashes", [])
            messages = [msg for _, msg in flashes]
            assert any("null_route" in m or "floating_rule" in m for m in messages)

    @patch("routes.settings_routes.get_db")
    @patch("routes.settings_routes.Config")
    def test_db_error_flashes(self, MockConfig, mock_get_db, client):
        MockConfig.DATABASE_PATH = ":memory:"
        mock_get_db.return_value.__enter__ = MagicMock(side_effect=RuntimeError("db fail"))
        mock_get_db.return_value.__exit__ = MagicMock(return_value=False)

        login(client)
        resp = client.post("/settings/update", data={
            "monitor_interval": "300",
            "default_block_method": "null_route",
        })

        assert resp.status_code == 302


class TestCreateFloatingRule:
    """Tests for POST /settings/floating-rule/<device_id>."""

    def test_requires_login(self, client):
        resp = client.post("/settings/floating-rule/1")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    @patch("routes.settings_routes.PfSenseClient")
    @patch("routes.settings_routes.Config")
    @patch("routes.settings_routes.BlocklistService")
    @patch("routes.settings_routes.DeviceManager")
    def test_success(self, MockDM, MockBLS, MockConfig, MockClient, client):
        MockConfig.DATABASE_PATH = ":memory:"
        device = {"id": 1, "hostname": "fw1", "device_type": "pfsense",
                  "web_username": "admin", "web_password": "pass"}
        MockDM.return_value.get_all_devices.return_value = [device]
        MockBLS.return_value.get_blocklist.return_value = [
            {"ip_address": "10.0.0.1"},
            {"ip_address": "10.0.0.2"},
        ]
        mock_client = MockClient.return_value

        login(client)
        resp = client.post("/settings/floating-rule/1")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "fw1" in data["message"]
        MockClient.assert_called_once_with(host="fw1", username="admin", password="pass")
        mock_client.ensure_alias_exists.assert_called_once_with("soc_blocklist", ["10.0.0.1", "10.0.0.2"])
        mock_client.create_floating_rule.assert_called_once_with("soc_blocklist")

    @patch("routes.settings_routes.Config")
    @patch("routes.settings_routes.DeviceManager")
    def test_device_not_found(self, MockDM, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        MockDM.return_value.get_all_devices.return_value = []

        login(client)
        resp = client.post("/settings/floating-rule/999")

        assert resp.status_code == 404
        data = resp.get_json()
        assert data["success"] is False
        assert "not found" in data["message"]

    @patch("routes.settings_routes.Config")
    @patch("routes.settings_routes.DeviceManager")
    def test_non_pfsense_device(self, MockDM, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        device = {"id": 1, "hostname": "lx1", "device_type": "linux"}
        MockDM.return_value.get_all_devices.return_value = [device]

        login(client)
        resp = client.post("/settings/floating-rule/1")

        assert resp.status_code == 400
        data = resp.get_json()
        assert data["success"] is False
        assert "pfSense" in data["message"]

    @patch("routes.settings_routes.PfSenseClient")
    @patch("routes.settings_routes.Config")
    @patch("routes.settings_routes.BlocklistService")
    @patch("routes.settings_routes.DeviceManager")
    def test_client_error(self, MockDM, MockBLS, MockConfig, MockClient, client):
        MockConfig.DATABASE_PATH = ":memory:"
        device = {"id": 1, "hostname": "fw1", "device_type": "pfsense",
                  "web_username": "admin", "web_password": "pass"}
        MockDM.return_value.get_all_devices.return_value = [device]
        MockBLS.return_value.get_blocklist.return_value = []
        MockClient.return_value.ensure_alias_exists.side_effect = RuntimeError("connection failed")

        login(client)
        resp = client.post("/settings/floating-rule/1")

        assert resp.status_code == 500
        data = resp.get_json()
        assert data["success"] is False
        assert "Failed" in data["message"] or "failed" in data["message"]

    @patch("routes.settings_routes.PfSenseClient")
    @patch("routes.settings_routes.Config")
    @patch("routes.settings_routes.BlocklistService")
    @patch("routes.settings_routes.DeviceManager")
    def test_empty_blocklist(self, MockDM, MockBLS, MockConfig, MockClient, client):
        MockConfig.DATABASE_PATH = ":memory:"
        device = {"id": 1, "hostname": "fw1", "device_type": "pfsense",
                  "web_username": "admin", "web_password": "pass"}
        MockDM.return_value.get_all_devices.return_value = [device]
        MockBLS.return_value.get_blocklist.return_value = []
        mock_client = MockClient.return_value

        login(client)
        resp = client.post("/settings/floating-rule/1")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        mock_client.ensure_alias_exists.assert_called_once_with("soc_blocklist", [])
        mock_client.create_floating_rule.assert_called_once_with("soc_blocklist")
