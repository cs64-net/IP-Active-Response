"""Unit tests for services/status_monitor.py — StatusMonitor class."""

from unittest.mock import MagicMock, patch

import pytest

from database import get_db, init_db
from services.status_monitor import StatusMonitor


@pytest.fixture
def db_path(tmp_path):
    """Provide a temporary database path with initialized schema."""
    path = str(tmp_path / "test.db")
    init_db(path)
    return path


@pytest.fixture
def monitor(db_path):
    return StatusMonitor(db_path=db_path, interval_seconds=60)


def _seed_pfsense(db_path, hostname="fw1"):
    with get_db(db_path) as conn:
        conn.execute(
            """INSERT INTO managed_devices
               (hostname, device_type, web_username, web_password, block_method)
               VALUES (?, 'pfsense', 'admin', 'pass', 'null_route')""",
            (hostname,),
        )
        return dict(conn.execute(
            "SELECT * FROM managed_devices WHERE hostname = ?", (hostname,)
        ).fetchone())


def _seed_linux(db_path, hostname="linux1"):
    with get_db(db_path) as conn:
        conn.execute(
            """INSERT INTO managed_devices
               (hostname, device_type, block_method, ssh_port, ssh_username, ssh_password)
               VALUES (?, 'linux', 'null_route', 22, 'root', 'pass')""",
            (hostname,),
        )
        return dict(conn.execute(
            "SELECT * FROM managed_devices WHERE hostname = ?", (hostname,)
        ).fetchone())


class TestCheckDevice:
    """Tests for StatusMonitor.check_device()."""

    @patch("services.status_monitor.PfSenseClient")
    def test_pfsense_online(self, mock_cls, monitor):
        mock_client = MagicMock()
        mock_client.check_health.return_value = True
        mock_cls.return_value = mock_client

        device = {"id": 1, "hostname": "fw1", "device_type": "pfsense",
                  "web_username": "admin", "web_password": "pass"}
        result = monitor.check_device(device)

        assert result == "online"
        mock_cls.assert_called_once_with(host="fw1", username="admin", password="pass")
        mock_client.check_health.assert_called_once()

    @patch("services.status_monitor.PfSenseClient")
    def test_pfsense_offline(self, mock_cls, monitor):
        mock_client = MagicMock()
        mock_client.check_health.return_value = False
        mock_cls.return_value = mock_client

        device = {"id": 1, "hostname": "fw1", "device_type": "pfsense",
                  "web_username": "admin", "web_password": "pass"}
        result = monitor.check_device(device)

        assert result == "offline"

    @patch("services.status_monitor.LinuxClient")
    def test_linux_online(self, mock_cls, monitor):
        mock_client = MagicMock()
        mock_client.check_health.return_value = True
        mock_cls.return_value = mock_client

        device = {"id": 2, "hostname": "linux1", "device_type": "linux",
                  "ssh_port": 22, "ssh_username": "root",
                  "ssh_password": "pass", "ssh_key_path": None}
        result = monitor.check_device(device)

        assert result == "online"
        mock_cls.assert_called_once_with(
            host="linux1", port=22, username="root",
            password="pass", key_path=None,
        )

    @patch("services.status_monitor.LinuxClient")
    def test_linux_offline(self, mock_cls, monitor):
        mock_client = MagicMock()
        mock_client.check_health.return_value = False
        mock_cls.return_value = mock_client

        device = {"id": 2, "hostname": "linux1", "device_type": "linux",
                  "ssh_port": 22, "ssh_username": "root",
                  "ssh_password": "pass", "ssh_key_path": None}
        result = monitor.check_device(device)

        assert result == "offline"

    def test_unknown_device_type_returns_offline(self, monitor):
        device = {"id": 3, "hostname": "mystery", "device_type": "unknown"}
        result = monitor.check_device(device)
        assert result == "offline"

    @patch("services.status_monitor.PfSenseClient")
    def test_exception_returns_offline(self, mock_cls, monitor):
        mock_cls.side_effect = Exception("connection error")

        device = {"id": 1, "hostname": "fw1", "device_type": "pfsense",
                  "web_username": "admin", "web_password": "pass"}
        result = monitor.check_device(device)

        assert result == "offline"


class TestCheckAllDevices:
    """Tests for StatusMonitor.check_all_devices()."""

    @patch("services.status_monitor.PfSenseClient")
    @patch("services.status_monitor.LinuxClient")
    def test_checks_all_devices_and_updates_db(self, mock_linux_cls, mock_pf_cls, monitor, db_path):
        pf_device = _seed_pfsense(db_path)
        lx_device = _seed_linux(db_path)

        mock_pf_cls.return_value.check_health.return_value = True
        mock_linux_cls.return_value.check_health.return_value = False

        results = monitor.check_all_devices()

        assert results[pf_device["id"]] == "online"
        assert results[lx_device["id"]] == "offline"

        # Verify DB was updated
        with get_db(db_path) as conn:
            pf_row = conn.execute(
                "SELECT status, last_checked FROM managed_devices WHERE id = ?",
                (pf_device["id"],),
            ).fetchone()
            assert pf_row["status"] == "online"
            assert pf_row["last_checked"] is not None

            lx_row = conn.execute(
                "SELECT status, last_checked FROM managed_devices WHERE id = ?",
                (lx_device["id"],),
            ).fetchone()
            assert lx_row["status"] == "offline"
            assert lx_row["last_checked"] is not None

    def test_no_devices_returns_empty(self, monitor):
        results = monitor.check_all_devices()
        assert results == {}

    @patch("services.status_monitor.PfSenseClient")
    def test_single_device(self, mock_cls, monitor, db_path):
        device = _seed_pfsense(db_path)
        mock_cls.return_value.check_health.return_value = True

        results = monitor.check_all_devices()

        assert len(results) == 1
        assert results[device["id"]] == "online"


class TestStartStop:
    """Tests for StatusMonitor.start() and stop()."""

    def test_start_creates_scheduler(self, monitor):
        monitor.start()
        assert monitor.scheduler is not None
        assert monitor.scheduler.running
        monitor.stop()

    def test_stop_shuts_down_scheduler(self, monitor):
        monitor.start()
        monitor.stop()
        assert monitor.scheduler is None

    def test_stop_without_start_is_safe(self, monitor):
        monitor.stop()  # Should not raise

    @patch("services.status_monitor.BackgroundScheduler")
    def test_start_configures_interval_job(self, mock_sched_cls, monitor):
        mock_scheduler = MagicMock()
        mock_sched_cls.return_value = mock_scheduler

        monitor.start()

        mock_scheduler.add_job.assert_called_once_with(
            monitor.check_all_devices,
            "interval",
            seconds=60,
            id="device_health_check",
        )
        mock_scheduler.start.assert_called_once()
