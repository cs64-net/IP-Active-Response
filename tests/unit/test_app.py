"""Unit tests for app.py — Flask application factory."""

from unittest.mock import MagicMock, patch

import pytest

from config import Config
from database import get_db, init_db


class TestConfig(Config):
    """Test configuration using a temporary database."""
    TESTING = True
    SECRET_KEY = "test-secret"


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "test.db")
    TestConfig.DATABASE_PATH = path
    init_db(path)
    return path


@pytest.fixture
def app(db_path):
    """Create a test app with StatusMonitor mocked to avoid real scheduling."""
    with patch("services.status_monitor.StatusMonitor") as mock_monitor_cls:
        mock_monitor = MagicMock()
        mock_monitor_cls.return_value = mock_monitor

        import app as app_module
        application = app_module.create_app(config_class=TestConfig)
        yield application

        app_module._status_monitor = None


@pytest.fixture
def client(app):
    return app.test_client()


class TestCreateApp:
    """Tests for the create_app factory."""

    def test_returns_flask_app(self, app):
        from flask import Flask
        assert isinstance(app, Flask)

    def test_config_loaded(self, app):
        assert app.config["SECRET_KEY"] == "test-secret"
        assert app.config["TESTING"] is True

    def test_database_initialized(self, db_path):
        """Database tables should exist after create_app."""
        with get_db(db_path) as conn:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            table_names = {r["name"] for r in tables}
            assert "users" in table_names
            assert "block_entries" in table_names
            assert "managed_devices" in table_names
            assert "push_statuses" in table_names
            assert "app_settings" in table_names


class TestBlueprintRegistration:
    """Tests that all route blueprints are registered."""

    def test_auth_blueprint_registered(self, app):
        assert "auth" in app.blueprints

    def test_dashboard_blueprint_registered(self, app):
        assert "dashboard" in app.blueprints

    def test_blocklist_blueprint_registered(self, app):
        assert "blocklist" in app.blueprints

    def test_devices_blueprint_registered(self, app):
        assert "devices" in app.blueprints

    def test_settings_blueprint_registered(self, app):
        assert "settings" in app.blueprints

    def test_all_five_blueprints(self, app):
        expected = {"auth", "dashboard", "blocklist", "devices", "settings"}
        assert expected.issubset(set(app.blueprints.keys()))


class TestStatusMonitor:
    """Tests that StatusMonitor is started during app creation."""

    def test_monitor_started(self, db_path):
        with patch("services.status_monitor.StatusMonitor") as mock_cls:
            mock_monitor = MagicMock()
            mock_cls.return_value = mock_monitor

            import app as app_module
            app_module.create_app(config_class=TestConfig)

            mock_monitor.start.assert_called_once()
            app_module._status_monitor = None

    def test_monitor_reads_interval_from_db(self, db_path):
        # Set a custom interval in the DB
        with get_db(db_path) as conn:
            conn.execute(
                "UPDATE app_settings SET monitor_interval = 120 WHERE id = 1"
            )

        with patch("services.status_monitor.StatusMonitor") as mock_cls:
            mock_monitor = MagicMock()
            mock_cls.return_value = mock_monitor

            import app as app_module
            app_module.create_app(config_class=TestConfig)

            mock_cls.assert_called_once_with(
                db_path=db_path, interval_seconds=120
            )
            app_module._status_monitor = None


class TestShutdownMonitor:
    """Tests for the atexit shutdown handler."""

    def test_shutdown_stops_monitor(self):
        import app as app_module
        mock_monitor = MagicMock()
        app_module._status_monitor = mock_monitor

        app_module._shutdown_monitor()

        mock_monitor.stop.assert_called_once()
        assert app_module._status_monitor is None

    def test_shutdown_with_no_monitor(self):
        import app as app_module
        app_module._status_monitor = None
        # Should not raise
        app_module._shutdown_monitor()


class TestErrorHandler:
    """Tests for the global 500 error handler."""

    def test_500_error_returns_500_status(self, app):
        @app.route("/test-error")
        def trigger_error():
            raise RuntimeError("test explosion")

        # Disable exception propagation so the error handler runs
        app.config["TESTING"] = False
        app.config["PROPAGATE_EXCEPTIONS"] = False

        with app.test_client() as c:
            resp = c.get("/test-error")
            assert resp.status_code == 500

    def test_500_error_logs_traceback(self, app):
        @app.route("/test-error-log")
        def trigger_error():
            raise ValueError("kaboom")

        app.config["TESTING"] = False
        app.config["PROPAGATE_EXCEPTIONS"] = False

        with patch("app.logger") as mock_logger:
            with app.test_client() as c:
                c.get("/test-error-log")
                mock_logger.error.assert_called()
                call_args = mock_logger.error.call_args
                assert "Unhandled exception" in call_args[0][0]
