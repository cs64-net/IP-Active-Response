# Feature: soc-ip-blocker, Property 4: Valid IP addition stores all metadata
# Feature: soc-ip-blocker, Property 5: Duplicate IP rejection preserves blocklist
# Feature: soc-ip-blocker, Property 6: Invalid IP addresses are rejected
# Feature: soc-ip-blocker, Property 7: IP removal removes from blocklist
"""Property-based tests for IP validation and blocklist operations."""

import ipaddress
import os
import tempfile

from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from database import init_db
from services.blocklist_service import BlocklistService


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

username_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=20,
)

note_strategy = st.text(max_size=100)

# Strategy for strings that are NOT valid IP addresses
invalid_ip_strategy = st.one_of(
    st.just(""),
    st.just("not.an.ip"),
    st.just("999.999.999.999"),
    st.just("256.1.1.1"),
    st.just("1.2.3.4.5"),
    st.just("abc::xyz"),
    st.just("12345"),
    st.just("1.2.3"),
    st.just("hello world"),
    st.text(
        alphabet=st.characters(whitelist_categories=("L", "P", "S")),
        min_size=1,
        max_size=30,
    ).filter(lambda s: not _is_valid_ip(s)),
)


def _is_valid_ip(s: str) -> bool:
    """Helper to check if a string is a valid IP address."""
    try:
        ipaddress.ip_address(s.strip())
        return True
    except (ValueError, AttributeError):
        return False


def fresh_db():
    """Create a fresh temporary database and return its path."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    return path


# --- Property 4: Valid IP addition stores all metadata ---


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    ip=valid_ip_strategy,
    user=username_strategy,
    note=note_strategy,
)
def test_valid_ip_addition_stores_all_metadata(ip: str, user: str, note: str):
    """**Validates: Requirements 2.1, 2.6**

    For any valid IPv4 or IPv6 address and optional note, adding it to the
    blocklist should result in a retrievable entry containing the IP address,
    timestamp, submitting user, and note.
    """
    db_path = fresh_db()
    try:
        service = BlocklistService(db_path=db_path)
        entry = service.add_ip(ip, user, note)

        # Verify the returned entry has all required metadata
        assert entry["ip_address"] == str(ipaddress.ip_address(ip))
        assert entry["added_by"] == user
        assert entry["note"] == note
        assert entry["added_at"] is not None

        # Verify it's retrievable from the blocklist
        blocklist = service.get_blocklist()
        matching = [e for e in blocklist if e["ip_address"] == entry["ip_address"]]
        assert len(matching) == 1

        retrieved = matching[0]
        assert retrieved["ip_address"] == entry["ip_address"]
        assert retrieved["added_by"] == user
        assert retrieved["note"] == note
        assert retrieved["added_at"] is not None
    finally:
        os.unlink(db_path)


# --- Property 5: Duplicate IP rejection preserves blocklist ---


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    ip=valid_ip_strategy,
    user1=username_strategy,
    note1=note_strategy,
    user2=username_strategy,
    note2=note_strategy,
)
def test_duplicate_ip_rejection_preserves_blocklist(
    ip: str, user1: str, note1: str, user2: str, note2: str
):
    """**Validates: Requirements 2.2**

    For any IP address already in the blocklist, attempting to add it again
    should be rejected and the blocklist size should remain unchanged.
    """
    db_path = fresh_db()
    try:
        service = BlocklistService(db_path=db_path)

        # First addition succeeds
        original_entry = service.add_ip(ip, user1, note1)
        blocklist_before = service.get_blocklist()
        size_before = len(blocklist_before)

        # Second addition of the same IP should be rejected
        duplicate_rejected = False
        try:
            service.add_ip(ip, user2, note2)
        except ValueError:
            duplicate_rejected = True

        assert duplicate_rejected, f"Duplicate IP {ip} should have been rejected"

        # Blocklist size should remain unchanged
        blocklist_after = service.get_blocklist()
        assert len(blocklist_after) == size_before

        # Original entry should still be intact
        matching = [
            e for e in blocklist_after
            if e["ip_address"] == original_entry["ip_address"]
        ]
        assert len(matching) == 1
        assert matching[0]["added_by"] == user1
        assert matching[0]["note"] == note1
    finally:
        os.unlink(db_path)


# --- Property 6: Invalid IP addresses are rejected ---


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(invalid_ip=invalid_ip_strategy)
def test_invalid_ip_addresses_are_rejected(invalid_ip: str):
    """**Validates: Requirements 2.3**

    For any string that is not a valid IPv4 or IPv6 address, the validate_ip
    function should return (False, error_message) and the blocklist should
    remain unchanged.
    """
    db_path = fresh_db()
    try:
        service = BlocklistService(db_path=db_path)

        # validate_ip should return (False, error_message)
        valid, error_msg = service.validate_ip(invalid_ip)
        assert valid is False, f"Expected invalid for '{invalid_ip}', got valid"
        assert isinstance(error_msg, str) and len(error_msg) > 0

        # Attempting to add should raise ValueError
        blocklist_before = service.get_blocklist()
        size_before = len(blocklist_before)

        try:
            service.add_ip(invalid_ip, "testuser", "test note")
        except ValueError:
            pass  # Expected

        # Blocklist should remain unchanged
        blocklist_after = service.get_blocklist()
        assert len(blocklist_after) == size_before
    finally:
        os.unlink(db_path)


# --- Property 7: IP removal removes from blocklist ---


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    ip=valid_ip_strategy,
    user=username_strategy,
    note=note_strategy,
)
def test_ip_removal_removes_from_blocklist(ip: str, user: str, note: str):
    """**Validates: Requirements 2.4**

    For any IP address currently in the blocklist, removing it should result
    in the IP no longer appearing in the blocklist.
    """
    db_path = fresh_db()
    try:
        service = BlocklistService(db_path=db_path)

        # Add the IP first
        entry = service.add_ip(ip, user, note)
        normalized_ip = entry["ip_address"]

        # Verify it's in the blocklist
        blocklist = service.get_blocklist()
        assert any(e["ip_address"] == normalized_ip for e in blocklist)

        # Remove it
        service.remove_ip(normalized_ip)

        # Verify it's no longer in the blocklist
        blocklist_after = service.get_blocklist()
        assert not any(e["ip_address"] == normalized_ip for e in blocklist_after), (
            f"IP {normalized_ip} should not appear in blocklist after removal"
        )
    finally:
        os.unlink(db_path)
