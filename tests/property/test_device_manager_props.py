# Feature: soc-ip-blocker, Property 13: Device onboarding round-trip
# Feature: soc-ip-blocker, Property 14: Device edit persists changes
# Feature: soc-ip-blocker, Property 15: Device removal removes from registry
"""Property-based tests for device manager CRUD operations."""

import os
import tempfile

from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from database import init_db
from services.device_manager import DeviceManager


# --- Strategies ---

hostname_strategy = st.one_of(
    # IP-style hostnames
    st.tuples(
        st.integers(min_value=1, max_value=254),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=1, max_value=254),
    ).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}"),
    # DNS-style hostnames
    st.text(
        alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="-_."),
        min_size=1,
        max_size=50,
    ).filter(lambda s: s[0].isalnum()),
)

username_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="_-"),
    min_size=1,
    max_size=30,
)

password_strategy = st.text(min_size=1, max_size=50)

block_method_strategy = st.sampled_from(["null_route", "floating_rule"])

ssh_port_strategy = st.integers(min_value=1, max_value=65535)

key_path_strategy = st.one_of(
    st.none(),
    st.text(
        alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="/._-"),
        min_size=1,
        max_size=100,
    ).map(lambda s: f"/home/user/.ssh/{s}"),
)

optional_password_strategy = st.one_of(st.none(), password_strategy)


def fresh_db():
    """Create a fresh temporary database and return its path."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    return path


# --- Property 13: Device onboarding round-trip ---


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    hostname=hostname_strategy,
    username=username_strategy,
    password=password_strategy,
    block_method=block_method_strategy,
)
def test_pfsense_onboarding_round_trip(
    hostname: str, username: str, password: str, block_method: str
):
    """**Validates: Requirements 6.1, 6.2**

    For any valid pfSense device configuration, adding the device and then
    retrieving it should return all stored fields with equivalent values.
    """
    db_path = fresh_db()
    try:
        dm = DeviceManager(db_path=db_path)
        device = dm.add_pfsense(hostname, username, password, block_method)

        # Verify returned device has correct fields
        assert device["hostname"] == hostname
        assert device["device_type"] == "pfsense"
        assert device["web_username"] == username
        assert device["web_password"] == password
        assert device["block_method"] == block_method

        # Verify round-trip: retrieve from DB and compare
        all_devices = dm.get_all_devices()
        assert len(all_devices) == 1
        retrieved = all_devices[0]
        assert retrieved["hostname"] == hostname
        assert retrieved["device_type"] == "pfsense"
        assert retrieved["web_username"] == username
        assert retrieved["web_password"] == password
        assert retrieved["block_method"] == block_method
        assert retrieved["id"] == device["id"]
    finally:
        os.unlink(db_path)


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    hostname=hostname_strategy,
    port=ssh_port_strategy,
    username=username_strategy,
    password=optional_password_strategy,
    key_path=key_path_strategy,
)
def test_linux_onboarding_round_trip(
    hostname: str, port: int, username: str, password, key_path
):
    """**Validates: Requirements 6.1, 6.2**

    For any valid Linux device configuration, adding the device and then
    retrieving it should return all stored fields with equivalent values.
    Linux devices should always have block_method set to "null_route".
    """
    db_path = fresh_db()
    try:
        dm = DeviceManager(db_path=db_path)
        device = dm.add_linux(hostname, port, username, password=password, key_path=key_path)

        # Verify returned device has correct fields
        assert device["hostname"] == hostname
        assert device["device_type"] == "linux"
        assert device["ssh_port"] == port
        assert device["ssh_username"] == username
        assert device["ssh_password"] == password
        assert device["ssh_key_path"] == key_path
        # Linux devices MUST always have block_method = "null_route"
        assert device["block_method"] == "null_route"

        # Verify round-trip: retrieve from DB and compare
        all_devices = dm.get_all_devices()
        assert len(all_devices) == 1
        retrieved = all_devices[0]
        assert retrieved["hostname"] == hostname
        assert retrieved["device_type"] == "linux"
        assert retrieved["ssh_port"] == port
        assert retrieved["ssh_username"] == username
        assert retrieved["ssh_password"] == password
        assert retrieved["ssh_key_path"] == key_path
        assert retrieved["block_method"] == "null_route"
        assert retrieved["id"] == device["id"]
    finally:
        os.unlink(db_path)


# --- Property 14: Device edit persists changes ---

# Strategy for valid update fields for pfSense devices
pfsense_update_strategy = st.fixed_dictionaries({}, optional={
    "hostname": hostname_strategy,
    "web_username": username_strategy,
    "web_password": password_strategy,
    "block_method": block_method_strategy,
}).filter(lambda d: len(d) > 0)

# Strategy for valid update fields for Linux devices
linux_update_strategy = st.fixed_dictionaries({}, optional={
    "hostname": hostname_strategy,
    "ssh_port": ssh_port_strategy,
    "ssh_username": username_strategy,
    "ssh_password": password_strategy,
    "ssh_key_path": key_path_strategy,
}).filter(lambda d: len(d) > 0)


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    hostname=hostname_strategy,
    username=username_strategy,
    password=password_strategy,
    block_method=block_method_strategy,
    updates=pfsense_update_strategy,
)
def test_pfsense_edit_persists_changes(
    hostname: str, username: str, password: str, block_method: str, updates: dict
):
    """**Validates: Requirements 6.3**

    For any existing pfSense device and any valid configuration update,
    editing the device should result in the stored configuration reflecting
    the new values.
    """
    db_path = fresh_db()
    try:
        dm = DeviceManager(db_path=db_path)
        device = dm.add_pfsense(hostname, username, password, block_method)

        updated = dm.update_device(device["id"], **updates)

        # Verify each updated field reflects the new value
        for key, value in updates.items():
            assert updated[key] == value, (
                f"Field '{key}' should be '{value}' but got '{updated[key]}'"
            )

        # Verify persistence: re-fetch from DB
        all_devices = dm.get_all_devices()
        retrieved = [d for d in all_devices if d["id"] == device["id"]][0]
        for key, value in updates.items():
            assert retrieved[key] == value, (
                f"Persisted field '{key}' should be '{value}' but got '{retrieved[key]}'"
            )
    finally:
        os.unlink(db_path)


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    hostname=hostname_strategy,
    port=ssh_port_strategy,
    username=username_strategy,
    updates=linux_update_strategy,
)
def test_linux_edit_persists_changes(
    hostname: str, port: int, username: str, updates: dict
):
    """**Validates: Requirements 6.3**

    For any existing Linux device and any valid configuration update,
    editing the device should result in the stored configuration reflecting
    the new values.
    """
    db_path = fresh_db()
    try:
        dm = DeviceManager(db_path=db_path)
        device = dm.add_linux(hostname, port, username)

        updated = dm.update_device(device["id"], **updates)

        # Verify each updated field reflects the new value
        for key, value in updates.items():
            assert updated[key] == value, (
                f"Field '{key}' should be '{value}' but got '{updated[key]}'"
            )

        # Verify persistence: re-fetch from DB
        all_devices = dm.get_all_devices()
        retrieved = [d for d in all_devices if d["id"] == device["id"]][0]
        for key, value in updates.items():
            assert retrieved[key] == value, (
                f"Persisted field '{key}' should be '{value}' but got '{retrieved[key]}'"
            )
    finally:
        os.unlink(db_path)


# --- Property 15: Device removal removes from registry ---


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    hostname=hostname_strategy,
    username=username_strategy,
    password=password_strategy,
    block_method=block_method_strategy,
)
def test_pfsense_removal_removes_from_registry(
    hostname: str, username: str, password: str, block_method: str
):
    """**Validates: Requirements 6.4**

    For any existing pfSense device, removing it should result in the device
    no longer appearing in the device list.
    """
    db_path = fresh_db()
    try:
        dm = DeviceManager(db_path=db_path)
        device = dm.add_pfsense(hostname, username, password, block_method)
        device_id = device["id"]

        # Confirm it exists
        assert any(d["id"] == device_id for d in dm.get_all_devices())

        # Remove it
        dm.remove_device(device_id)

        # Verify it no longer appears
        all_devices = dm.get_all_devices()
        assert not any(d["id"] == device_id for d in all_devices), (
            f"Device {device_id} should not appear after removal"
        )
    finally:
        os.unlink(db_path)


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    hostname=hostname_strategy,
    port=ssh_port_strategy,
    username=username_strategy,
    password=optional_password_strategy,
    key_path=key_path_strategy,
)
def test_linux_removal_removes_from_registry(
    hostname: str, port: int, username: str, password, key_path
):
    """**Validates: Requirements 6.4**

    For any existing Linux device, removing it should result in the device
    no longer appearing in the device list.
    """
    db_path = fresh_db()
    try:
        dm = DeviceManager(db_path=db_path)
        device = dm.add_linux(hostname, port, username, password=password, key_path=key_path)
        device_id = device["id"]

        # Confirm it exists
        assert any(d["id"] == device_id for d in dm.get_all_devices())

        # Remove it
        dm.remove_device(device_id)

        # Verify it no longer appears
        all_devices = dm.get_all_devices()
        assert not any(d["id"] == device_id for d in all_devices), (
            f"Device {device_id} should not appear after removal"
        )
    finally:
        os.unlink(db_path)
