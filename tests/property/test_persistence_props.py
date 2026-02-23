# Feature: soc-ip-blocker, Property 22: Data persistence round-trip
"""Property-based tests for data persistence round-trip verification."""

import os
import tempfile

from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from database import init_db, get_db
from services.blocklist_service import BlocklistService
from services.device_manager import DeviceManager


# --- Strategies ---

ipv4_strategy = st.tuples(
    st.integers(min_value=1, max_value=254),
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=1, max_value=254),
).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}")

username_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=20,
)

note_strategy = st.text(max_size=100)

hostname_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters=".-"),
    min_size=1,
    max_size=50,
).filter(lambda s: s[0].isalnum())

block_method_strategy = st.sampled_from(["null_route", "floating_rule"])

ssh_port_strategy = st.integers(min_value=1, max_value=65535)


# --- Helpers ---

def fresh_db():
    """Create a fresh temporary database and return its path."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    return path


# --- Tests ---

@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    ip=ipv4_strategy,
    user=username_strategy,
    note=note_strategy,
)
def test_blocklist_entry_persists_across_connections(ip: str, user: str, note: str):
    """**Validates: Requirements 12.1, 12.2**

    For any blocklist entry written to the database, the data should be fully
    retrievable after closing and reopening the database connection.
    """
    db_path = fresh_db()
    try:
        # Write via first connection
        service = BlocklistService(db_path=db_path)
        entry = service.add_ip(ip, user, note)

        # Read via a new service instance (new connection)
        service2 = BlocklistService(db_path=db_path)
        blocklist = service2.get_blocklist()

        matching = [e for e in blocklist if e["ip_address"] == entry["ip_address"]]
        assert len(matching) == 1, f"Expected 1 entry for {ip}, got {len(matching)}"

        retrieved = matching[0]
        assert retrieved["ip_address"] == entry["ip_address"]
        assert retrieved["added_by"] == user
        assert retrieved["note"] == note
        assert retrieved["added_at"] is not None
    finally:
        os.unlink(db_path)


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    hostname=hostname_strategy,
    web_user=username_strategy,
    web_pass=username_strategy,
    block_method=block_method_strategy,
)
def test_pfsense_device_persists_across_connections(
    hostname: str, web_user: str, web_pass: str, block_method: str
):
    """**Validates: Requirements 12.1, 12.2**

    For any pfSense device configuration written to the database, the data should
    be fully retrievable after closing and reopening the database connection.
    """
    db_path = fresh_db()
    try:
        dm = DeviceManager(db_path=db_path)
        device = dm.add_pfsense(hostname, web_user, web_pass, block_method)

        dm2 = DeviceManager(db_path=db_path)
        devices = dm2.get_all_devices()

        matching = [d for d in devices if d["id"] == device["id"]]
        assert len(matching) == 1

        retrieved = matching[0]
        assert retrieved["hostname"] == hostname
        assert retrieved["device_type"] == "pfsense"
        assert retrieved["web_username"] == web_user
        assert retrieved["web_password"] == web_pass
        assert retrieved["block_method"] == block_method
    finally:
        os.unlink(db_path)


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    hostname=hostname_strategy,
    port=ssh_port_strategy,
    ssh_user=username_strategy,
    ssh_pass=username_strategy,
)
def test_linux_device_persists_across_connections(
    hostname: str, port: int, ssh_user: str, ssh_pass: str
):
    """**Validates: Requirements 12.1, 12.2**

    For any Linux device configuration written to the database, the data should
    be fully retrievable after closing and reopening the database connection.
    """
    db_path = fresh_db()
    try:
        dm = DeviceManager(db_path=db_path)
        device = dm.add_linux(hostname, port, ssh_user, password=ssh_pass)

        dm2 = DeviceManager(db_path=db_path)
        devices = dm2.get_all_devices()

        matching = [d for d in devices if d["id"] == device["id"]]
        assert len(matching) == 1

        retrieved = matching[0]
        assert retrieved["hostname"] == hostname
        assert retrieved["device_type"] == "linux"
        assert retrieved["block_method"] == "null_route"
        assert retrieved["ssh_port"] == port
        assert retrieved["ssh_username"] == ssh_user
        assert retrieved["ssh_password"] == ssh_pass
    finally:
        os.unlink(db_path)


# Feature: soc-ip-blocker, Property 23: Transaction atomicity on failure


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    ip=ipv4_strategy,
    user=username_strategy,
    note=note_strategy,
    hostname=hostname_strategy,
)
def test_transaction_atomicity_on_failure(ip: str, user: str, note: str, hostname: str):
    """**Validates: Requirements 12.3**

    For any write operation that fails partway through, the database should not
    contain partial data from that operation.

    We simulate a multi-step write inside a single get_db() transaction where the
    second step raises an error. The first step's data should be rolled back.
    """
    db_path = fresh_db()
    try:
        # Attempt a transaction that inserts a block entry and then a device with
        # an invalid device_type, which violates the CHECK constraint and causes
        # the transaction to fail. Neither the block entry nor the device should
        # persist.
        try:
            with get_db(db_path) as conn:
                # Step 1: insert a valid block entry
                conn.execute(
                    "INSERT INTO block_entries (ip_address, added_by, note) VALUES (?, ?, ?)",
                    (ip, user, note),
                )
                # Step 2: insert a device with invalid device_type to trigger CHECK failure
                conn.execute(
                    """INSERT INTO managed_devices (hostname, device_type)
                       VALUES (?, 'INVALID_TYPE')""",
                    (hostname,),
                )
        except Exception:
            pass  # Expected — the CHECK constraint violation causes rollback

        # Verify: no partial data from the failed transaction
        with get_db(db_path) as conn:
            block_rows = conn.execute(
                "SELECT * FROM block_entries WHERE ip_address = ?", (ip,)
            ).fetchall()
            device_rows = conn.execute(
                "SELECT * FROM managed_devices WHERE hostname = ?", (hostname,)
            ).fetchall()

        assert len(block_rows) == 0, (
            f"Block entry for {ip} should not exist after failed transaction, "
            f"but found {len(block_rows)} row(s)"
        )
        assert len(device_rows) == 0, (
            f"Device {hostname} should not exist after failed transaction, "
            f"but found {len(device_rows)} row(s)"
        )
    finally:
        os.unlink(db_path)


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    ip=ipv4_strategy,
    user=username_strategy,
    note=note_strategy,
)
def test_transaction_atomicity_service_layer_duplicate(ip: str, user: str, note: str):
    """**Validates: Requirements 12.3**

    For any IP that is successfully added, a second add of the same IP should fail
    and the blocklist should still contain exactly one entry for that IP (the
    original). The failed duplicate insert must not corrupt or remove the first entry.
    """
    db_path = fresh_db()
    try:
        service = BlocklistService(db_path=db_path)

        # First add succeeds
        entry = service.add_ip(ip, user, note)

        # Second add should raise ValueError (duplicate)
        try:
            service.add_ip(ip, "other_user", "other note")
        except ValueError:
            pass

        # Verify exactly one entry exists with original data intact
        blocklist = service.get_blocklist()
        matching = [e for e in blocklist if e["ip_address"] == entry["ip_address"]]
        assert len(matching) == 1, (
            f"Expected exactly 1 entry for {ip}, got {len(matching)}"
        )
        assert matching[0]["added_by"] == user
        assert matching[0]["note"] == note
    finally:
        os.unlink(db_path)


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    ip=ipv4_strategy,
    user=username_strategy,
    note=note_strategy,
)
def test_transaction_atomicity_exception_during_write(ip: str, user: str, note: str):
    """**Validates: Requirements 12.3**

    For any write operation that is interrupted by an arbitrary exception after
    executing SQL but before the context manager commits, the database should
    contain no data from that operation.
    """
    db_path = fresh_db()
    try:
        # Simulate an exception raised after a successful INSERT but before commit
        try:
            with get_db(db_path) as conn:
                conn.execute(
                    "INSERT INTO block_entries (ip_address, added_by, note) VALUES (?, ?, ?)",
                    (ip, user, note),
                )
                raise RuntimeError("Simulated failure before commit")
        except RuntimeError:
            pass

        # Verify: the block entry should not exist
        with get_db(db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM block_entries WHERE ip_address = ?", (ip,)
            ).fetchall()

        assert len(rows) == 0, (
            f"Block entry for {ip} should not exist after exception rolled back "
            f"the transaction, but found {len(rows)} row(s)"
        )
    finally:
        os.unlink(db_path)
