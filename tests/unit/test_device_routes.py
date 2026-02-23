"""Unit tests for routes/device_routes.py — device CRUD and test routes."""

import pytest
from unittest.mock import patch, MagicMock

from flask import Blueprint, Flask

from routes.device_routes import devices_bp


def create_test_app():
    """Create a minimal Flask app for testing device routes."""
    app = Flask(__name__)
    app.secret_key = "test-secret"
    app.config["TESTING"] = True

    # Stub settings blueprint so url_for('settings.index') resolves
    settings_bp = Blueprint("settings", __name__)

    @settings_bp.route("/settings")
    def index():
        return "settings"

    # Stub auth blueprint so login_required redirect resolves
    from routes.auth_routes import auth_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(devices_bp)
    return app


@pytest.fixture
def app():
    return create_test_app()


@pytest.fixture
def client(app):
    return app.test_client()


def login(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"


class TestAddDevice:
    """Tests for POST /devices/add."""

    def test_requires_login(self, client):
        resp = client.post("/devices/add", data={"device_type": "pfsense"})
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    @patch("routes.device_routes.Config")
    @patch("routes.device_routes.DeviceManager")
    def test_add_pfsense(self, MockDM, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        mock_dm = MockDM.return_value

        login(client)
        resp = client.post("/devices/add", data={
            "device_type": "pfsense",
            "hostname": "10.0.0.1",
            "username": "admin",
            "password": "secret",
            "block_method": "null_route",
        })

        assert resp.status_code == 302
        assert "/settings" in resp.headers["Location"]
        mock_dm.add_pfsense.assert_called_once_with(
            "10.0.0.1", "admin", "secret", "null_route", ""
        )

    @patch("routes.device_routes.Config")
    @patch("routes.device_routes.DeviceManager")
    def test_add_linux(self, MockDM, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        mock_dm = MockDM.return_value

        login(client)
        resp = client.post("/devices/add", data={
            "device_type": "linux",
            "hostname": "192.168.1.10",
            "port": "2222",
            "username": "root",
            "password": "pass",
            "key_path": "",
        })

        assert resp.status_code == 302
        mock_dm.add_linux.assert_called_once_with(
            "192.168.1.10", 2222, "root", "pass", None, "", "", sudo_password=""
        )

    @patch("routes.device_routes.Config")
    @patch("routes.device_routes.DeviceManager")
    def test_add_linux_with_key(self, MockDM, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        mock_dm = MockDM.return_value

        login(client)
        resp = client.post("/devices/add", data={
            "device_type": "linux",
            "hostname": "192.168.1.10",
            "port": "22",
            "username": "root",
            "password": "",
            "key_path": "/home/user/.ssh/id_rsa",
        })

        assert resp.status_code == 302
        mock_dm.add_linux.assert_called_once_with(
            "192.168.1.10", 22, "root", None, "/home/user/.ssh/id_rsa", "", "", sudo_password=""
        )

    @patch("routes.device_routes.Config")
    @patch("routes.device_routes.DeviceManager")
    def test_add_invalid_type_flashes_error(self, MockDM, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"

        login(client)
        resp = client.post("/devices/add", data={"device_type": "unknown"})

        assert resp.status_code == 302
        MockDM.return_value.add_pfsense.assert_not_called()
        MockDM.return_value.add_linux.assert_not_called()

    @patch("routes.device_routes.Config")
    @patch("routes.device_routes.DeviceManager")
    def test_add_value_error_flashes(self, MockDM, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        MockDM.return_value.add_pfsense.side_effect = ValueError("Invalid block_method")

        login(client)
        resp = client.post("/devices/add", data={
            "device_type": "pfsense",
            "hostname": "fw1",
            "username": "admin",
            "password": "pass",
            "block_method": "bad",
        })

        assert resp.status_code == 302


class TestEditDevice:
    """Tests for POST /devices/edit/<id>."""

    def test_requires_login(self, client):
        resp = client.post("/devices/edit/1", data={"hostname": "new"})
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    @patch("routes.device_routes.Config")
    @patch("routes.device_routes.DeviceManager")
    def test_edit_device(self, MockDM, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        mock_dm = MockDM.return_value

        login(client)
        resp = client.post("/devices/edit/1", data={
            "hostname": "new-host",
            "block_method": "floating_rule",
        })

        assert resp.status_code == 302
        assert "/settings" in resp.headers["Location"]
        mock_dm.update_device.assert_called_once_with(
            1, hostname="new-host", block_method="floating_rule"
        )

    @patch("routes.device_routes.Config")
    @patch("routes.device_routes.DeviceManager")
    def test_edit_with_ssh_port(self, MockDM, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        mock_dm = MockDM.return_value

        login(client)
        resp = client.post("/devices/edit/2", data={"ssh_port": "2222"})

        assert resp.status_code == 302
        mock_dm.update_device.assert_called_once_with(2, ssh_port=2222)

    @patch("routes.device_routes.Config")
    @patch("routes.device_routes.DeviceManager")
    def test_edit_not_found(self, MockDM, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        MockDM.return_value.update_device.side_effect = ValueError("not found")

        login(client)
        resp = client.post("/devices/edit/999", data={"hostname": "x"})

        assert resp.status_code == 302


class TestRemoveDevice:
    """Tests for POST /devices/remove/<id>."""

    def test_requires_login(self, client):
        resp = client.post("/devices/remove/1")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    @patch("routes.device_routes.Config")
    @patch("routes.device_routes.DeviceManager")
    def test_remove_device(self, MockDM, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        mock_dm = MockDM.return_value

        login(client)
        resp = client.post("/devices/remove/1")

        assert resp.status_code == 302
        assert "/settings" in resp.headers["Location"]
        mock_dm.remove_device.assert_called_once_with(1)

    @patch("routes.device_routes.Config")
    @patch("routes.device_routes.DeviceManager")
    def test_remove_not_found(self, MockDM, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        MockDM.return_value.remove_device.side_effect = ValueError("not found")

        login(client)
        resp = client.post("/devices/remove/999")

        assert resp.status_code == 302


class TestTestDevice:
    """Tests for POST /devices/test/<id>."""

    def test_requires_login(self, client):
        resp = client.post("/devices/test/1")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    @patch("routes.device_routes.Config")
    @patch("routes.device_routes.StatusMonitor")
    @patch("routes.device_routes.DeviceManager")
    def test_device_online(self, MockDM, MockMonitor, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        device = {"id": 1, "hostname": "fw1", "device_type": "pfsense"}
        MockDM.return_value.get_all_devices.return_value = [device]
        MockMonitor.return_value.check_device.return_value = "online"

        login(client)
        resp = client.post("/devices/test/1")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "successful" in data["message"]

    @patch("routes.device_routes.Config")
    @patch("routes.device_routes.StatusMonitor")
    @patch("routes.device_routes.DeviceManager")
    def test_device_offline(self, MockDM, MockMonitor, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        device = {"id": 1, "hostname": "fw1", "device_type": "pfsense"}
        MockDM.return_value.get_all_devices.return_value = [device]
        MockMonitor.return_value.check_device.return_value = "offline"

        login(client)
        resp = client.post("/devices/test/1")

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is False
        assert "failed" in data["message"]

    @patch("routes.device_routes.Config")
    @patch("routes.device_routes.StatusMonitor")
    @patch("routes.device_routes.DeviceManager")
    def test_device_not_found(self, MockDM, MockMonitor, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        MockDM.return_value.get_all_devices.return_value = []

        login(client)
        resp = client.post("/devices/test/999")

        assert resp.status_code == 404
        data = resp.get_json()
        assert data["success"] is False

    @patch("routes.device_routes.Config")
    @patch("routes.device_routes.StatusMonitor")
    @patch("routes.device_routes.DeviceManager")
    def test_device_exception(self, MockDM, MockMonitor, MockConfig, client):
        MockConfig.DATABASE_PATH = ":memory:"
        MockDM.return_value.get_all_devices.side_effect = RuntimeError("db error")

        login(client)
        resp = client.post("/devices/test/1")

        assert resp.status_code == 500
        data = resp.get_json()
        assert data["success"] is False
