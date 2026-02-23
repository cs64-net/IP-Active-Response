"""Unit tests for services/blocklist_service.py — BlocklistService."""

import pytest

from database import get_db, init_db
from services.blocklist_service import BlocklistService


@pytest.fixture
def db_path(tmp_path):
    """Provide a temporary database path for each test."""
    path = str(tmp_path / "test.db")
    init_db(path)
    return path


@pytest.fixture
def service(db_path):
    """Provide a BlocklistService instance with a temp database."""
    return BlocklistService(db_path=db_path)


class TestValidateIp:
    """Tests for validate_ip()."""

    def test_valid_ipv4(self, service):
        valid, msg = service.validate_ip("192.168.1.1")
        assert valid is True
        assert msg == ""

    def test_valid_ipv6(self, service):
        valid, msg = service.validate_ip("::1")
        assert valid is True
        assert msg == ""

    def test_valid_ipv6_full(self, service):
        valid, msg = service.validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert valid is True

    def test_invalid_ip_garbage(self, service):
        valid, msg = service.validate_ip("not-an-ip")
        assert valid is False
        assert msg != ""

    def test_invalid_ip_empty(self, service):
        valid, msg = service.validate_ip("")
        assert valid is False

    def test_invalid_ip_cidr(self, service):
        valid, msg = service.validate_ip("10.0.0.0/33")
        assert valid is False

    def test_strips_whitespace(self, service):
        valid, msg = service.validate_ip("  10.0.0.1  ")
        assert valid is True


class TestAddIp:
    """Tests for add_ip()."""

    def test_add_valid_ipv4(self, service, db_path):
        entry = service.add_ip("10.0.0.1", "analyst1")
        assert entry["ip_address"] == "10.0.0.1"
        assert entry["added_by"] == "analyst1"
        assert entry["note"] == ""
        assert entry["id"] is not None
        assert entry["added_at"] is not None

    def test_add_valid_ipv6(self, service):
        entry = service.add_ip("::1", "analyst1")
        assert entry["ip_address"] == "::1"

    def test_add_with_note(self, service):
        entry = service.add_ip("10.0.0.2", "analyst1", note="Suspicious traffic")
        assert entry["note"] == "Suspicious traffic"

    def test_add_invalid_ip_raises(self, service):
        with pytest.raises(ValueError, match="Invalid IP address"):
            service.add_ip("bad-ip", "analyst1")

    def test_add_duplicate_raises(self, service):
        service.add_ip("10.0.0.1", "analyst1")
        with pytest.raises(ValueError, match="already in the blocklist"):
            service.add_ip("10.0.0.1", "analyst2")

    def test_add_normalizes_ip(self, service):
        entry = service.add_ip("  10.0.0.1  ", "analyst1")
        assert entry["ip_address"] == "10.0.0.1"

    def test_add_persists_to_db(self, service, db_path):
        service.add_ip("172.16.0.1", "analyst1")
        with get_db(db_path) as conn:
            row = conn.execute(
                "SELECT ip_address FROM block_entries WHERE ip_address = ?",
                ("172.16.0.1",),
            ).fetchone()
            assert row is not None


class TestRemoveIp:
    """Tests for remove_ip()."""

    def test_remove_existing_ip(self, service, db_path):
        service.add_ip("10.0.0.1", "analyst1")
        service.remove_ip("10.0.0.1")
        with get_db(db_path) as conn:
            row = conn.execute(
                "SELECT id FROM block_entries WHERE ip_address = '10.0.0.1'"
            ).fetchone()
            assert row is None

    def test_remove_nonexistent_raises(self, service):
        with pytest.raises(ValueError, match="not found"):
            service.remove_ip("10.0.0.99")

    def test_remove_cascades_push_statuses(self, service, db_path):
        service.add_ip("10.0.0.1", "analyst1")
        # Insert a device and push status manually
        with get_db(db_path) as conn:
            conn.execute(
                "INSERT INTO managed_devices (hostname, device_type) VALUES ('fw1', 'pfsense')"
            )
            entry_id = conn.execute(
                "SELECT id FROM block_entries WHERE ip_address = '10.0.0.1'"
            ).fetchone()["id"]
            conn.execute(
                "INSERT INTO push_statuses (block_entry_id, device_id, status) VALUES (?, 1, 'success')",
                (entry_id,),
            )
        service.remove_ip("10.0.0.1")
        with get_db(db_path) as conn:
            count = conn.execute("SELECT COUNT(*) FROM push_statuses").fetchone()[0]
            assert count == 0


class TestGetBlocklist:
    """Tests for get_blocklist()."""

    def test_empty_blocklist(self, service):
        result = service.get_blocklist()
        assert result == []

    def test_returns_entries(self, service):
        service.add_ip("10.0.0.1", "analyst1", note="test")
        service.add_ip("10.0.0.2", "analyst2")
        result = service.get_blocklist()
        assert len(result) == 2
        ips = {e["ip_address"] for e in result}
        assert ips == {"10.0.0.1", "10.0.0.2"}

    def test_entries_include_push_statuses(self, service, db_path):
        service.add_ip("10.0.0.1", "analyst1")
        # Add a device and push status
        with get_db(db_path) as conn:
            conn.execute(
                "INSERT INTO managed_devices (hostname, device_type) VALUES ('fw1', 'pfsense')"
            )
            entry_id = conn.execute(
                "SELECT id FROM block_entries WHERE ip_address = '10.0.0.1'"
            ).fetchone()["id"]
            conn.execute(
                "INSERT INTO push_statuses (block_entry_id, device_id, status) VALUES (?, 1, 'success')",
                (entry_id,),
            )
        result = service.get_blocklist()
        assert len(result) == 1
        assert len(result[0]["push_statuses"]) == 1
        ps = result[0]["push_statuses"][0]
        assert ps["status"] == "success"
        assert ps["hostname"] == "fw1"
        assert ps["device_type"] == "pfsense"

    def test_entries_without_push_statuses(self, service):
        service.add_ip("10.0.0.1", "analyst1")
        result = service.get_blocklist()
        assert len(result) == 1
        assert result[0]["push_statuses"] == []

    def test_ordered_by_added_at_desc(self, service, db_path):
        # Insert with explicit timestamps to control order
        with get_db(db_path) as conn:
            conn.execute(
                "INSERT INTO block_entries (ip_address, added_by, added_at) VALUES (?, ?, ?)",
                ("10.0.0.1", "user1", "2024-01-01 00:00:00"),
            )
            conn.execute(
                "INSERT INTO block_entries (ip_address, added_by, added_at) VALUES (?, ?, ?)",
                ("10.0.0.2", "user2", "2024-06-01 00:00:00"),
            )
        result = service.get_blocklist()
        assert result[0]["ip_address"] == "10.0.0.2"
        assert result[1]["ip_address"] == "10.0.0.1"


class TestCIDRValidation:
    def test_validate_cidr_v4(self, service):
        valid, msg = service.validate_ip("10.0.0.0/24")
        assert valid is True

    def test_validate_cidr_v4_host(self, service):
        valid, msg = service.validate_ip("192.168.1.1/32")
        assert valid is True

    def test_validate_cidr_v6(self, service):
        valid, msg = service.validate_ip("2001:db8::/48")
        assert valid is True

    def test_validate_invalid_cidr(self, service):
        valid, msg = service.validate_ip("10.0.0.0/33")
        assert valid is False

    def test_validate_plain_ip_still_works(self, service):
        valid, msg = service.validate_ip("1.1.1.1")
        assert valid is True
