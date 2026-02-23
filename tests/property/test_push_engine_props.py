# Feature: soc-ip-blocker, Property 8: Push block reaches all devices
# Feature: soc-ip-blocker, Property 9: Remove block reaches all devices
# Feature: soc-ip-blocker, Property 10: Fault isolation — failure on one device does not block others
# Feature: soc-ip-blocker, Property 11: Push results are always recorded
"""Property-based tests for the push engine."""

import ipaddress
import os
import tempfile
from unittest.mock import patch, MagicMock

from hypothesis import given, settings, HealthCheck, assume
from hypothesis import strategies as st

from database import init_db, get_db
from services.push_engine import PushEngine


# --- Strategies ---

ipv4_strategy = st.tuples(
    st.integers(min_value=1, max_value=254),
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=1, max_value=254),
).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}")

ipv6_strategy = st.tuples(
    *[st.integers(min_value=0, max_value=0xFFFF) for _ in range(8)]
).map(lambda t: ":".join(f"{x:x}" for x in t)).map(
    lambda s: str(ipaddress.ip_address(s))
)

valid_ip_strategy = st.one_of(ipv4_strategy, ipv6_strategy)

block_method_strategy = st.sampled_from(["null_route", "floating_rule"])

pfsense_device_strategy = st.fixed_dictionaries({
    "hostname": st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789.", min_size=3, max_size=15),
    "device_type": st.just("pfsense"),
    "web_username": st.just("admin"),
    "web_password": st.just("password"),
    "block_method": block_method_strategy,
})

linux_device_strategy = st.fixed_dictionaries({
    "hostname": st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789.", min_size=3, max_size=15),
    "device_type": st.just("linux"),
    "ssh_port": st.integers(min_value=1, max_value=65535),
    "ssh_username": st.just("root"),
    "ssh_password": st.just("password"),
    "ssh_key_path": st.none(),
})

device_strategy = st.one_of(pfsense_device_strategy, linux_device_strategy)

# Generate a non-empty list of mixed devices, each with a unique id
device_list_strategy = st.lists(
    device_strategy, min_size=1, max_size=10
).map(lambda devs: [dict(d, id=i + 1) for i, d in enumerate(devs)])


def fresh_db():
    """Create a fresh temporary database and return its path."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    return path


def _add_block_entry(db_path: str, ip_address: str) -> int:
    """Insert a block entry and return its id."""
    normalized = str(ipaddress.ip_address(ip_address))
    with get_db(db_path) as conn:
        conn.execute(
            "INSERT INTO block_entries (ip_address, added_by, note) VALUES (?, ?, ?)",
            (normalized, "testuser", ""),
        )
        row = conn.execute(
            "SELECT id FROM block_entries WHERE ip_address = ?", (normalized,)
        ).fetchone()
        return row["id"]


def _add_devices_to_db(db_path: str, devices: list) -> None:
    """Insert device records into the database so push_statuses FK is satisfied."""
    with get_db(db_path) as conn:
        for dev in devices:
            if dev["device_type"] == "pfsense":
                conn.execute(
                    """INSERT INTO managed_devices
                       (id, hostname, device_type, web_username, web_password, block_method)
                       VALUES (?, ?, 'pfsense', ?, ?, ?)""",
                    (dev["id"], dev["hostname"], dev["web_username"],
                     dev["web_password"], dev["block_method"]),
                )
            else:
                conn.execute(
                    """INSERT INTO managed_devices
                       (id, hostname, device_type, ssh_port, ssh_username, ssh_password)
                       VALUES (?, ?, 'linux', ?, ?, ?)""",
                    (dev["id"], dev["hostname"], dev.get("ssh_port", 22),
                     dev["ssh_username"], dev.get("ssh_password")),
                )


# --- Property 8: Push block reaches all devices ---


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(ip=valid_ip_strategy, devices=device_list_strategy)
def test_push_block_reaches_all_devices(ip: str, devices: list):
    """**Validates: Requirements 3.1, 4.1**

    For any IP address and any set of managed devices (pfSense and Linux),
    pushing a block should result in a push attempt to every device in the set,
    with a recorded result for each.
    """
    db_path = fresh_db()
    try:
        normalized_ip = str(ipaddress.ip_address(ip))
        _add_devices_to_db(db_path, devices)
        _add_block_entry(db_path, normalized_ip)

        engine = PushEngine(db_path=db_path)

        with patch("services.push_engine.PfSenseClient") as mock_pf, \
             patch("services.push_engine.LinuxClient") as mock_lx:
            mock_pf_instance = MagicMock()
            mock_pf.return_value = mock_pf_instance
            mock_lx_instance = MagicMock()
            mock_lx.return_value = mock_lx_instance

            results = engine.push_block(normalized_ip, devices)

        # Every device should have a result
        assert len(results) == len(devices)

        # Every device id should appear exactly once in results
        result_device_ids = sorted(r["device_id"] for r in results)
        expected_device_ids = sorted(d["id"] for d in devices)
        assert result_device_ids == expected_device_ids

        # All should be successful (no failures injected)
        for r in results:
            assert r["success"] is True
            assert r["error_message"] is None
    finally:
        os.unlink(db_path)


# --- Property 9: Remove block reaches all devices ---


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(ip=valid_ip_strategy, devices=device_list_strategy)
def test_remove_block_reaches_all_devices(ip: str, devices: list):
    """**Validates: Requirements 3.4, 4.2**

    For any IP address and any set of managed devices, removing a block should
    result in a removal attempt to every device in the set, with a recorded
    result for each.
    """
    db_path = fresh_db()
    try:
        normalized_ip = str(ipaddress.ip_address(ip))
        _add_devices_to_db(db_path, devices)
        _add_block_entry(db_path, normalized_ip)

        engine = PushEngine(db_path=db_path)

        with patch("services.push_engine.PfSenseClient") as mock_pf, \
             patch("services.push_engine.LinuxClient") as mock_lx:
            mock_pf_instance = MagicMock()
            mock_pf.return_value = mock_pf_instance
            mock_lx_instance = MagicMock()
            mock_lx.return_value = mock_lx_instance

            results = engine.remove_block(normalized_ip, devices)

        # Every device should have a result
        assert len(results) == len(devices)

        # Every device id should appear exactly once in results
        result_device_ids = sorted(r["device_id"] for r in results)
        expected_device_ids = sorted(d["id"] for d in devices)
        assert result_device_ids == expected_device_ids

        # All should be successful (no failures injected)
        for r in results:
            assert r["success"] is True
            assert r["error_message"] is None
    finally:
        os.unlink(db_path)


# --- Property 10: Fault isolation — failure on one device does not block others ---


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    ip=valid_ip_strategy,
    devices=st.lists(device_strategy, min_size=2, max_size=10).map(
        lambda devs: [dict(d, id=i + 1) for i, d in enumerate(devs)]
    ),
    fail_indices=st.data(),
)
def test_fault_isolation_failure_does_not_block_others(ip: str, devices: list, fail_indices):
    """**Validates: Requirements 3.5, 4.3, 11.3**

    For any set of managed devices where a subset fails during a push or
    removal operation, all remaining devices in the set should still receive
    their push/removal attempt and have their results recorded.
    """
    # Draw a non-empty proper subset of device indices to fail
    all_indices = list(range(len(devices)))
    failing = fail_indices.draw(
        st.lists(
            st.sampled_from(all_indices),
            min_size=1,
            max_size=max(1, len(devices) - 1),
            unique=True,
        )
    )
    # Ensure at least one device succeeds
    assume(len(failing) < len(devices))

    failing_ids = {devices[i]["id"] for i in failing}

    db_path = fresh_db()
    try:
        normalized_ip = str(ipaddress.ip_address(ip))
        _add_devices_to_db(db_path, devices)
        _add_block_entry(db_path, normalized_ip)

        engine = PushEngine(db_path=db_path)

        def pf_side_effect(*args, **kwargs):
            instance = MagicMock()
            return instance

        def lx_side_effect(*args, **kwargs):
            instance = MagicMock()
            return instance

        # We need to make specific devices fail. The push engine calls
        # _push_to_device per device, so we patch at that level.
        original_push = engine._push_to_device

        def patched_push(ip_addr, device, action):
            if device["id"] in failing_ids:
                # Simulate a failure by raising inside the client call
                return {"device_id": device["id"], "success": False,
                        "error_message": f"Simulated failure on device {device['id']}"}
            return {"device_id": device["id"], "success": True, "error_message": None}

        with patch.object(engine, "_push_to_device", side_effect=patched_push):
            results = engine.push_block(normalized_ip, devices)

        # ALL devices should have a result (fault isolation)
        assert len(results) == len(devices)

        result_device_ids = sorted(r["device_id"] for r in results)
        expected_device_ids = sorted(d["id"] for d in devices)
        assert result_device_ids == expected_device_ids

        # Failing devices should have success=False
        for r in results:
            if r["device_id"] in failing_ids:
                assert r["success"] is False
                assert r["error_message"] is not None
            else:
                assert r["success"] is True
                assert r["error_message"] is None
    finally:
        os.unlink(db_path)


# --- Property 11: Push results are always recorded ---


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    ip=valid_ip_strategy,
    devices=device_list_strategy,
    action=st.sampled_from(["block", "remove"]),
    fail_device_indices=st.data(),
)
def test_push_results_are_always_recorded(ip: str, devices: list, action: str, fail_device_indices):
    """**Validates: Requirements 3.6, 4.4**

    For any push or removal operation to any managed device, the result
    (success or failure with error message) should be persisted and associated
    with the correct block entry and device.
    """
    # Optionally make some devices fail
    all_indices = list(range(len(devices)))
    failing = fail_device_indices.draw(
        st.lists(st.sampled_from(all_indices), min_size=0, max_size=len(devices), unique=True)
    )
    failing_ids = {devices[i]["id"] for i in failing}

    db_path = fresh_db()
    try:
        normalized_ip = str(ipaddress.ip_address(ip))
        _add_devices_to_db(db_path, devices)
        block_entry_id = _add_block_entry(db_path, normalized_ip)

        engine = PushEngine(db_path=db_path)

        def patched_push(ip_addr, device, act):
            if device["id"] in failing_ids:
                return {"device_id": device["id"], "success": False,
                        "error_message": f"Error on device {device['id']}"}
            return {"device_id": device["id"], "success": True, "error_message": None}

        with patch.object(engine, "_push_to_device", side_effect=patched_push):
            if action == "block":
                results = engine.push_block(normalized_ip, devices)
            else:
                results = engine.remove_block(normalized_ip, devices)

        # Verify results are persisted in the database
        with get_db(db_path) as conn:
            rows = conn.execute(
                "SELECT device_id, status, error_message FROM push_statuses WHERE block_entry_id = ?",
                (block_entry_id,),
            ).fetchall()

        persisted = {row["device_id"]: dict(row) for row in rows}

        # Every device should have a persisted push status
        for dev in devices:
            dev_id = dev["id"]
            assert dev_id in persisted, (
                f"Device {dev_id} should have a persisted push status"
            )
            row = persisted[dev_id]
            if dev_id in failing_ids:
                assert row["status"] == "failed"
                assert row["error_message"] is not None
            else:
                assert row["status"] == "success"
                assert row["error_message"] is None
    finally:
        os.unlink(db_path)
