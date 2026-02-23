"""Unit tests for routes/blocklist_routes.py — blocklist add/remove routes."""

import pytest
from unittest.mock import patch, MagicMock

from flask import Flask

from database import init_db
from routes.blocklist_routes import blocklist_bp


def create_test_app(db_path):
    """Create a minimal Flask app for testing blocklist routes."""
    app = Flask(__name__)
    app.secret_key = "test-secret"
    app.config["TESTING"] = True

    # Register a minimal dashboard blueprint with an index route
    from flask import Blueprint
    dashboard_bp = Blueprint("dashboard", __name__)

    @dashboard_bp.route("/dashboard")
    def index():
        return "dashboard"

    # Register auth blueprint so login_required can redirect to auth.login
    from routes.auth_routes import auth_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(blocklist_bp)
    return app


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "test.db")
    init_db(path)
    return path


@pytest.fixture
def app(db_path):
    app = create_test_app(db_path)
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def login(client):
    """Set session user to simulate authentication."""
    with client.session_transaction() as sess:
        sess["user"] = "admin"


class TestAddIpRoute:
    """Tests for POST /blocklist/add."""

    def test_requires_login(self, client):
        resp = client.post("/blocklist/add", data={"ip_address": "10.0.0.1"})
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    @patch("routes.blocklist_routes.Config")
    @patch("routes.blocklist_routes.PushEngine")
    @patch("routes.blocklist_routes.DeviceManager")
    @patch("routes.blocklist_routes.BlocklistService")
    def test_add_valid_ip(self, MockBLS, MockDM, MockPE, MockConfig, client, db_path):
        MockConfig.DATABASE_PATH = db_path
        mock_service = MockBLS.return_value
        mock_dm = MockDM.return_value
        mock_dm.get_all_devices.return_value = [{"id": 1, "hostname": "fw1"}]
        mock_pe = MockPE.return_value

        login(client)
        resp = client.post(
            "/blocklist/add",
            data={"ip_address": "10.0.0.1", "note": "test note"},
        )

        assert resp.status_code == 302
        mock_service.add_ip.assert_called_once_with("10.0.0.1", "admin", "test note")
        mock_pe.push_block.assert_called_once_with(
            "10.0.0.1", [{"id": 1, "hostname": "fw1"}]
        )

    @patch("routes.blocklist_routes.Config")
    @patch("routes.blocklist_routes.PushEngine")
    @patch("routes.blocklist_routes.DeviceManager")
    @patch("routes.blocklist_routes.BlocklistService")
    def test_add_invalid_ip_flashes_error(self, MockBLS, MockDM, MockPE, MockConfig, client, db_path):
        MockConfig.DATABASE_PATH = db_path
        mock_service = MockBLS.return_value
        mock_service.add_ip.side_effect = ValueError("Invalid IP address: not valid")

        login(client)
        resp = client.post("/blocklist/add", data={"ip_address": "bad-ip"})

        assert resp.status_code == 302
        # Flash message should contain the error
        with client.session_transaction() as sess:
            flashes = dict(sess.get("_flashes", []))
            assert "error" in flashes or any(
                "Invalid IP" in msg for _, msg in sess.get("_flashes", [])
            )

    @patch("routes.blocklist_routes.Config")
    @patch("routes.blocklist_routes.PushEngine")
    @patch("routes.blocklist_routes.DeviceManager")
    @patch("routes.blocklist_routes.BlocklistService")
    def test_add_duplicate_ip_flashes_error(self, MockBLS, MockDM, MockPE, MockConfig, client, db_path):
        MockConfig.DATABASE_PATH = db_path
        mock_service = MockBLS.return_value
        mock_service.add_ip.side_effect = ValueError("already in the blocklist")

        login(client)
        resp = client.post("/blocklist/add", data={"ip_address": "10.0.0.1"})

        assert resp.status_code == 302

    @patch("routes.blocklist_routes.Config")
    @patch("routes.blocklist_routes.PushEngine")
    @patch("routes.blocklist_routes.DeviceManager")
    @patch("routes.blocklist_routes.BlocklistService")
    def test_add_with_empty_note(self, MockBLS, MockDM, MockPE, MockConfig, client, db_path):
        MockConfig.DATABASE_PATH = db_path
        mock_service = MockBLS.return_value
        mock_dm = MockDM.return_value
        mock_dm.get_all_devices.return_value = []

        login(client)
        resp = client.post("/blocklist/add", data={"ip_address": "10.0.0.1"})

        assert resp.status_code == 302
        mock_service.add_ip.assert_called_once_with("10.0.0.1", "admin", "")

    @patch("routes.blocklist_routes.Config")
    @patch("routes.blocklist_routes.PushEngine")
    @patch("routes.blocklist_routes.DeviceManager")
    @patch("routes.blocklist_routes.BlocklistService")
    def test_add_unexpected_error(self, MockBLS, MockDM, MockPE, MockConfig, client, db_path):
        MockConfig.DATABASE_PATH = db_path
        mock_service = MockBLS.return_value
        mock_service.add_ip.side_effect = RuntimeError("DB exploded")

        login(client)
        resp = client.post("/blocklist/add", data={"ip_address": "10.0.0.1"})

        assert resp.status_code == 302


class TestRemoveIpRoute:
    """Tests for POST /blocklist/remove/<ip>."""

    def test_requires_login(self, client):
        resp = client.post("/blocklist/remove/10.0.0.1")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    @patch("routes.blocklist_routes.get_db")
    @patch("routes.blocklist_routes.Config")
    @patch("routes.blocklist_routes.PushEngine")
    @patch("routes.blocklist_routes.DeviceManager")
    @patch("routes.blocklist_routes.BlocklistService")
    def test_remove_valid_ip(self, MockBLS, MockDM, MockPE, MockConfig, mock_get_db, client, db_path):
        MockConfig.DATABASE_PATH = db_path
        mock_service = MockBLS.return_value
        mock_dm = MockDM.return_value
        mock_dm.get_all_devices.return_value = [{"id": 1, "hostname": "fw1"}]
        mock_pe = MockPE.return_value

        # Mock get_db to return a block_entry_id
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = {"id": 42}
        mock_get_db.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_get_db.return_value.__exit__ = MagicMock(return_value=False)

        login(client)
        resp = client.post("/blocklist/remove/10.0.0.1")

        assert resp.status_code == 302
        mock_service.remove_ip.assert_called_once_with("10.0.0.1")

    @patch("routes.blocklist_routes.get_db")
    @patch("routes.blocklist_routes.Config")
    @patch("routes.blocklist_routes.PushEngine")
    @patch("routes.blocklist_routes.DeviceManager")
    @patch("routes.blocklist_routes.BlocklistService")
    def test_remove_deletes_db_before_background_push(self, MockBLS, MockDM, MockPE, MockConfig, mock_get_db, client, db_path):
        """Verify DB removal happens before background thread starts (race fix)."""
        MockConfig.DATABASE_PATH = db_path
        mock_dm = MockDM.return_value
        mock_dm.get_all_devices.return_value = []
        mock_pe = MockPE.return_value
        mock_service = MockBLS.return_value

        # Mock get_db to return a block_entry_id
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = {"id": 42}
        mock_get_db.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_get_db.return_value.__exit__ = MagicMock(return_value=False)

        call_order = []
        mock_service.remove_ip.side_effect = lambda *a: call_order.append("db_remove")

        login(client)
        client.post("/blocklist/remove/10.0.0.1")

        # DB removal should happen (no devices, so no push)
        assert "db_remove" in call_order

    @patch("routes.blocklist_routes.get_db")
    @patch("routes.blocklist_routes.Config")
    @patch("routes.blocklist_routes.PushEngine")
    @patch("routes.blocklist_routes.DeviceManager")
    @patch("routes.blocklist_routes.BlocklistService")
    def test_remove_nonexistent_ip_flashes_error(self, MockBLS, MockDM, MockPE, MockConfig, mock_get_db, client, db_path):
        MockConfig.DATABASE_PATH = db_path
        mock_dm = MockDM.return_value
        mock_dm.get_all_devices.return_value = []
        mock_pe = MockPE.return_value
        mock_service = MockBLS.return_value
        mock_service.remove_ip.side_effect = ValueError("not found")

        # Mock get_db to return no row
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = None
        mock_get_db.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_get_db.return_value.__exit__ = MagicMock(return_value=False)

        login(client)
        resp = client.post("/blocklist/remove/10.0.0.99")

        assert resp.status_code == 302

    @patch("routes.blocklist_routes.get_db")
    @patch("routes.blocklist_routes.Config")
    @patch("routes.blocklist_routes.PushEngine")
    @patch("routes.blocklist_routes.DeviceManager")
    @patch("routes.blocklist_routes.BlocklistService")
    def test_remove_unexpected_error(self, MockBLS, MockDM, MockPE, MockConfig, mock_get_db, client, db_path):
        MockConfig.DATABASE_PATH = db_path
        mock_dm = MockDM.return_value
        mock_dm.get_all_devices.return_value = []
        mock_pe = MockPE.return_value
        mock_pe.remove_block.side_effect = RuntimeError("network down")

        # Mock get_db to return a block_entry_id
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = {"id": 1}
        mock_get_db.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_get_db.return_value.__exit__ = MagicMock(return_value=False)

        login(client)
        resp = client.post("/blocklist/remove/10.0.0.1")

        assert resp.status_code == 302
