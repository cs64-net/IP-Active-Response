"""Unit tests for DeviceManager service."""

import pytest

from database import init_db
from services.device_manager import DeviceManager


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "test.db")
    init_db(path)
    return path


@pytest.fixture
def dm(db_path):
    return DeviceManager(db_path=db_path)


class TestAddPfsense:
    def test_adds_pfsense_device(self, dm):
        device = dm.add_pfsense("192.168.1.1", "admin", "pass", "null_route")
        assert device["hostname"] == "192.168.1.1"
        assert device["device_type"] == "pfsense"
        assert device["web_username"] == "admin"
        assert device["web_password"] == "pass"
        assert device["block_method"] == "null_route"

    def test_floating_rule_method(self, dm):
        device = dm.add_pfsense("fw1.local", "root", "secret", "floating_rule")
        assert device["block_method"] == "floating_rule"

    def test_invalid_block_method_raises(self, dm):
        with pytest.raises(ValueError, match="Invalid block_method"):
            dm.add_pfsense("fw1", "admin", "pass", "invalid")

    def test_returns_id(self, dm):
        device = dm.add_pfsense("fw1", "admin", "pass", "null_route")
        assert device["id"] is not None
        assert isinstance(device["id"], int)

    def test_default_status_unknown(self, dm):
        device = dm.add_pfsense("fw1", "admin", "pass", "null_route")
        assert device["status"] == "unknown"


class TestAddLinux:
    def test_adds_linux_device(self, dm):
        device = dm.add_linux("10.0.0.5", 22, "root", password="pass123")
        assert device["hostname"] == "10.0.0.5"
        assert device["device_type"] == "linux"
        assert device["ssh_port"] == 22
        assert device["ssh_username"] == "root"
        assert device["ssh_password"] == "pass123"

    def test_block_method_forced_null_route(self, dm):
        device = dm.add_linux("host1", 22, "user")
        assert device["block_method"] == "null_route"

    def test_with_key_path(self, dm):
        device = dm.add_linux("host1", 2222, "deploy", key_path="/home/deploy/.ssh/id_rsa")
        assert device["ssh_key_path"] == "/home/deploy/.ssh/id_rsa"
        assert device["ssh_port"] == 2222

    def test_password_and_key_both_none(self, dm):
        device = dm.add_linux("host1", 22, "user")
        assert device["ssh_password"] is None
        assert device["ssh_key_path"] is None


class TestUpdateDevice:
    def test_update_hostname(self, dm):
        device = dm.add_pfsense("old.host", "admin", "pass", "null_route")
        updated = dm.update_device(device["id"], hostname="new.host")
        assert updated["hostname"] == "new.host"

    def test_update_multiple_fields(self, dm):
        device = dm.add_pfsense("fw1", "admin", "pass", "null_route")
        updated = dm.update_device(device["id"], web_username="newadmin", block_method="floating_rule")
        assert updated["web_username"] == "newadmin"
        assert updated["block_method"] == "floating_rule"

    def test_update_nonexistent_raises(self, dm):
        with pytest.raises(ValueError, match="not found"):
            dm.update_device(9999, hostname="x")

    def test_update_no_fields_raises(self, dm):
        device = dm.add_pfsense("fw1", "admin", "pass", "null_route")
        with pytest.raises(ValueError, match="No fields"):
            dm.update_device(device["id"])

    def test_update_invalid_field_raises(self, dm):
        device = dm.add_pfsense("fw1", "admin", "pass", "null_route")
        with pytest.raises(ValueError, match="Invalid fields"):
            dm.update_device(device["id"], nonexistent_field="val")

    def test_update_preserves_other_fields(self, dm):
        device = dm.add_pfsense("fw1", "admin", "pass", "null_route")
        updated = dm.update_device(device["id"], hostname="fw2")
        assert updated["web_username"] == "admin"
        assert updated["block_method"] == "null_route"


class TestRemoveDevice:
    def test_remove_existing(self, dm):
        device = dm.add_pfsense("fw1", "admin", "pass", "null_route")
        dm.remove_device(device["id"])
        assert dm.get_all_devices() == []

    def test_remove_nonexistent_raises(self, dm):
        with pytest.raises(ValueError, match="not found"):
            dm.remove_device(9999)


class TestGetAllDevices:
    def test_empty_initially(self, dm):
        assert dm.get_all_devices() == []

    def test_returns_all_types(self, dm):
        dm.add_pfsense("fw1", "admin", "pass", "null_route")
        dm.add_linux("lx1", 22, "root")
        devices = dm.get_all_devices()
        assert len(devices) == 2
        types = {d["device_type"] for d in devices}
        assert types == {"pfsense", "linux"}


class TestGetDevicesByType:
    def test_filter_pfsense(self, dm):
        dm.add_pfsense("fw1", "admin", "pass", "null_route")
        dm.add_linux("lx1", 22, "root")
        pf = dm.get_devices_by_type("pfsense")
        assert len(pf) == 1
        assert pf[0]["device_type"] == "pfsense"

    def test_filter_linux(self, dm):
        dm.add_pfsense("fw1", "admin", "pass", "null_route")
        dm.add_linux("lx1", 22, "root")
        lx = dm.get_devices_by_type("linux")
        assert len(lx) == 1
        assert lx[0]["device_type"] == "linux"

    def test_no_matches(self, dm):
        dm.add_pfsense("fw1", "admin", "pass", "null_route")
        assert dm.get_devices_by_type("linux") == []
