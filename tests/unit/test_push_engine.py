"""Unit tests for services/push_engine.py — PushEngine class."""

from unittest.mock import MagicMock, patch

import pytest

from database import get_db, init_db
from services.push_engine import PushEngine, PFSENSE_ALIAS_NAME


@pytest.fixture
def db_path(tmp_path):
    """Provide a temporary database path with initialized schema."""
    path = str(tmp_path / "test.db")
    init_db(path)
    return path


@pytest.fixture
def engine(db_path):
    return PushEngine(db_path=db_path)


def _seed_block_entry(db_path, ip="10.0.0.1"):
    """Insert a block entry and return its id."""
    with get_db(db_path) as conn:
        conn.execute(
            "INSERT INTO block_entries (ip_address, added_by) VALUES (?, 'admin')",
            (ip,),
        )
        return conn.execute(
            "SELECT id FROM block_entries WHERE ip_address = ?", (ip,)
        ).fetchone()["id"]


def _seed_pfsense(db_path, hostname="fw1", block_method="null_route"):
    with get_db(db_path) as conn:
        conn.execute(
            """INSERT INTO managed_devices
               (hostname, device_type, web_username, web_password, block_method)
               VALUES (?, 'pfsense', 'admin', 'pass', ?)""",
            (hostname, block_method),
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


class TestPushBlock:
    """Tests for PushEngine.push_block()."""

    def test_empty_devices_returns_empty(self, engine):
        results = engine.push_block("10.0.0.1", [])
        assert results == []

    @patch("services.push_engine.PfSenseClient")
    def test_pfsense_null_route(self, mock_cls, engine, db_path):
        _seed_block_entry(db_path)
        device = _seed_pfsense(db_path, block_method="null_route")

        mock_client = MagicMock()
        mock_cls.return_value = mock_client

        results = engine.push_block("10.0.0.1", [device])

        mock_cls.assert_called_once_with(
            host=device["hostname"],
            username=device["web_username"],
            password=device["web_password"],
        )
        mock_client.add_null_route.assert_called_once_with("10.0.0.1")
        assert len(results) == 1
        assert results[0]["success"] is True
        assert results[0]["device_id"] == device["id"]

    @patch("services.push_engine.PfSenseClient")
    def test_pfsense_floating_rule(self, mock_cls, engine, db_path):
        _seed_block_entry(db_path)
        device = _seed_pfsense(db_path, block_method="floating_rule")

        mock_client = MagicMock()
        mock_cls.return_value = mock_client

        results = engine.push_block("10.0.0.1", [device])

        mock_client.ensure_alias_exists.assert_called_once_with(PFSENSE_ALIAS_NAME, ["10.0.0.1"])
        assert results[0]["success"] is True

    @patch("services.push_engine.LinuxClient")
    def test_linux_null_route(self, mock_cls, engine, db_path):
        _seed_block_entry(db_path)
        device = _seed_linux(db_path)

        mock_client = MagicMock()
        mock_cls.return_value = mock_client

        results = engine.push_block("10.0.0.1", [device])

        mock_cls.assert_called_once_with(
            host=device["hostname"],
            port=22,
            username=device["ssh_username"],
            password=device["ssh_password"],
            key_path=device.get("ssh_key_path"),
            key_content=device.get("ssh_key"),
            sudo_password=device.get("sudo_password"),
        )
        mock_client.add_null_route.assert_called_once_with("10.0.0.1")
        assert results[0]["success"] is True

    @patch("services.push_engine.PfSenseClient")
    def test_failure_records_error(self, mock_cls, engine, db_path):
        _seed_block_entry(db_path)
        device = _seed_pfsense(db_path)

        mock_client = MagicMock()
        mock_client.add_null_route.side_effect = Exception("Connection refused")
        mock_cls.return_value = mock_client

        results = engine.push_block("10.0.0.1", [device])

        assert results[0]["success"] is False
        assert "Connection refused" in results[0]["error_message"]

    @patch("services.push_engine.PfSenseClient")
    @patch("services.push_engine.LinuxClient")
    def test_stores_push_statuses_in_db(self, mock_linux_cls, mock_pf_cls, engine, db_path):
        entry_id = _seed_block_entry(db_path)
        pf_device = _seed_pfsense(db_path)
        lx_device = _seed_linux(db_path)

        mock_pf_cls.return_value = MagicMock()
        mock_linux_cls.return_value = MagicMock()

        engine.push_block("10.0.0.1", [pf_device, lx_device])

        with get_db(db_path) as conn:
            statuses = conn.execute(
                "SELECT * FROM push_statuses WHERE block_entry_id = ?", (entry_id,)
            ).fetchall()
            assert len(statuses) == 2
            for s in statuses:
                assert s["status"] == "success"

    @patch("services.push_engine.PfSenseClient")
    @patch("services.push_engine.LinuxClient")
    def test_fault_isolation(self, mock_linux_cls, mock_pf_cls, engine, db_path):
        """One device failure should not prevent others from being pushed."""
        _seed_block_entry(db_path)
        pf_device = _seed_pfsense(db_path)
        lx_device = _seed_linux(db_path)

        mock_pf_client = MagicMock()
        mock_pf_client.add_null_route.side_effect = Exception("pfSense down")
        mock_pf_cls.return_value = mock_pf_client

        mock_linux_cls.return_value = MagicMock()

        results = engine.push_block("10.0.0.1", [pf_device, lx_device])

        assert len(results) == 2
        result_map = {r["device_id"]: r for r in results}
        assert result_map[pf_device["id"]]["success"] is False
        assert result_map[lx_device["id"]]["success"] is True


class TestRemoveBlock:
    """Tests for PushEngine.remove_block()."""

    def test_empty_devices_returns_empty(self, engine):
        results = engine.remove_block("10.0.0.1", [])
        assert results == []

    @patch("services.push_engine.PfSenseClient")
    def test_pfsense_null_route_removal(self, mock_cls, engine, db_path):
        _seed_block_entry(db_path)
        device = _seed_pfsense(db_path, block_method="null_route")

        mock_client = MagicMock()
        mock_cls.return_value = mock_client

        results = engine.remove_block("10.0.0.1", [device])

        mock_client.remove_null_route.assert_called_once_with("10.0.0.1")
        assert results[0]["success"] is True

    @patch("services.push_engine.PfSenseClient")
    def test_pfsense_floating_rule_removal(self, mock_cls, engine, db_path):
        _seed_block_entry(db_path)
        device = _seed_pfsense(db_path, block_method="floating_rule")

        mock_client = MagicMock()
        mock_cls.return_value = mock_client

        results = engine.remove_block("10.0.0.1", [device])

        mock_client.ensure_alias_exists.assert_called_once_with(PFSENSE_ALIAS_NAME, ["10.0.0.1"])
        assert results[0]["success"] is True

    @patch("services.push_engine.LinuxClient")
    def test_linux_removal(self, mock_cls, engine, db_path):
        _seed_block_entry(db_path)
        device = _seed_linux(db_path)

        mock_client = MagicMock()
        mock_cls.return_value = mock_client

        results = engine.remove_block("10.0.0.1", [device])

        mock_client.remove_null_route.assert_called_once_with("10.0.0.1")
        assert results[0]["success"] is True

    @patch("services.push_engine.PfSenseClient")
    def test_stores_failed_status_in_db(self, mock_cls, engine, db_path):
        entry_id = _seed_block_entry(db_path)
        device = _seed_pfsense(db_path)

        mock_client = MagicMock()
        mock_client.remove_null_route.side_effect = Exception("timeout")
        mock_cls.return_value = mock_client

        engine.remove_block("10.0.0.1", [device])

        with get_db(db_path) as conn:
            row = conn.execute(
                "SELECT status, error_message FROM push_statuses WHERE block_entry_id = ? AND device_id = ?",
                (entry_id, device["id"]),
            ).fetchone()
            assert row["status"] == "failed"
            assert "timeout" in row["error_message"]
