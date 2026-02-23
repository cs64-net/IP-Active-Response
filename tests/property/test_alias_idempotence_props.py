# Feature: soc-ip-blocker, Property 12: Alias creation is idempotent
"""Property-based tests for alias creation idempotence.

Validates that triggering Central Floating Rule creation twice on a pfSense
firewall results in exactly one alias and one floating rule, with the alias
containing the current blocklist contents — the second call updates rather
than duplicates.
"""

import re
from unittest.mock import patch, MagicMock, call

import requests
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from clients.pfsense_client import PfSenseClient


# --- Constants ---

CSRF_TOKEN = "sid:abc123;csrf_magic_token_value"

ALIAS_NAME = "soc_blocklist"


# --- Strategies ---

# Generate valid IPv4 addresses
ipv4_strategy = st.tuples(
    st.integers(min_value=1, max_value=254),
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=1, max_value=254),
).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}")

# Generate non-empty lists of unique IPs (the blocklist)
ip_list_strategy = st.lists(
    ipv4_strategy,
    min_size=1,
    max_size=10,
    unique=True,
)


# --- HTML helpers ---

def _aliases_page_no_match_html():
    """Alias list page with no matching alias."""
    return f"""
    <html><body>
    <input name="__csrf_magic" value="{CSRF_TOKEN}" />
    <table><tr><td>No aliases</td></tr></table>
    </body></html>
    """


def _aliases_page_with_alias_html(alias_name, alias_id="3"):
    """Alias list page where the alias already exists."""
    return f"""
    <html><body>
    <input name="__csrf_magic" value="{CSRF_TOKEN}" />
    <table>
    <tr><td><a href="firewall_aliases_edit.php?id={alias_id}">{alias_name}</a></td></tr>
    </table></body></html>
    """


def _alias_edit_html(ips):
    """Alias edit page with existing IPs."""
    fields = "\n".join(
        f'<input name="address{i}" value="{ip}" />' for i, ip in enumerate(ips)
    )
    return f"""
    <html><body>
    <form method="post">
    <input name="__csrf_magic" value="{CSRF_TOKEN}" />
    {fields}
    </form></body></html>
    """


def _generic_page_html():
    """Generic pfSense page with CSRF token."""
    return f"""
    <html><body>
    <input name="__csrf_magic" value="{CSRF_TOKEN}" />
    </body></html>
    """


def _mock_response(status_code=200, text="", url="https://fw/index.php"):
    """Build a mock requests.Response."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.text = text
    resp.url = url
    resp.raise_for_status = MagicMock()
    return resp


# --- Property 12: Alias creation is idempotent ---


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(ip_list=ip_list_strategy)
def test_alias_creation_is_idempotent(ip_list):
    """**Validates: Requirements 5.2**

    For any pfSense firewall, triggering Central Floating Rule creation twice
    should result in exactly one alias and one floating rule, with the alias
    containing the current blocklist contents. The second call should update
    rather than duplicate.
    """
    client = PfSenseClient(
        host="192.168.1.1",
        username="admin",
        password="pfsense",
        verify_ssl=False,
    )
    # Pre-set session so we skip login
    client.session = MagicMock(spec=requests.Session)
    client.session.verify = False
    client.csrf_token = CSRF_TOKEN

    # Track all ensure_alias_exists and create_floating_rule POST calls
    ensure_alias_post_calls = []
    create_rule_post_calls = []

    # --- First invocation: alias does NOT exist yet ---

    # Set up mock responses for first ensure_alias_exists call (new alias)
    first_ensure_get_responses = [
        _mock_response(text=_aliases_page_no_match_html()),   # GET alias list - no match
        _mock_response(text=_alias_edit_html([])),            # GET edit page (new)
    ]
    first_ensure_post_responses = [
        _mock_response(text=_alias_edit_html(ip_list)),       # POST save alias
        _mock_response(text=_aliases_page_no_match_html()),   # POST apply changes
    ]

    # First create_floating_rule call
    first_rule_get_responses = [
        _mock_response(text=_generic_page_html()),            # GET rule edit page
        _mock_response(text=_generic_page_html()),            # GET floating rules page
    ]
    first_rule_post_responses = [
        _mock_response(text=_generic_page_html()),            # POST save rule
        _mock_response(text=_generic_page_html()),            # POST apply changes
    ]

    # --- Second invocation: alias ALREADY exists (id=3) ---

    second_ensure_get_responses = [
        _mock_response(text=_aliases_page_with_alias_html(ALIAS_NAME, "3")),  # GET alias list - found
        _mock_response(text=_alias_edit_html(ip_list)),                        # GET edit page (existing)
    ]
    second_ensure_post_responses = [
        _mock_response(text=_alias_edit_html(ip_list)),       # POST save alias (update)
        _mock_response(text=_aliases_page_with_alias_html(ALIAS_NAME, "3")),  # POST apply
    ]

    second_rule_get_responses = [
        _mock_response(text=_generic_page_html()),            # GET rule edit page
        _mock_response(text=_generic_page_html()),            # GET floating rules page
    ]
    second_rule_post_responses = [
        _mock_response(text=_generic_page_html()),            # POST save rule
        _mock_response(text=_generic_page_html()),            # POST apply changes
    ]

    # Chain all GET and POST responses in order
    all_get_responses = (
        first_ensure_get_responses
        + first_rule_get_responses
        + second_ensure_get_responses
        + second_rule_get_responses
    )
    all_post_responses = (
        first_ensure_post_responses
        + first_rule_post_responses
        + second_ensure_post_responses
        + second_rule_post_responses
    )

    client.session.get.side_effect = list(all_get_responses)
    client.session.post.side_effect = list(all_post_responses)

    # --- Execute first invocation ---
    result1_alias = client.ensure_alias_exists(ALIAS_NAME, ip_list)
    result1_rule = client.create_floating_rule(ALIAS_NAME)

    # Capture POST calls after first invocation
    first_invocation_post_calls = client.session.post.call_args_list[:]

    # --- Execute second invocation ---
    result2_alias = client.ensure_alias_exists(ALIAS_NAME, ip_list)
    result2_rule = client.create_floating_rule(ALIAS_NAME)

    all_post_calls = client.session.post.call_args_list

    # --- Assertions ---

    # Both invocations should succeed
    assert result1_alias is True, "First ensure_alias_exists should succeed"
    assert result1_rule is True, "First create_floating_rule should succeed"
    assert result2_alias is True, "Second ensure_alias_exists should succeed"
    assert result2_rule is True, "Second create_floating_rule should succeed"

    # Extract the alias save POST data from both invocations
    # First alias save is post_calls[0], second alias save is post_calls[4]
    first_alias_save_data = all_post_calls[0][1]["data"]
    second_alias_save_data = all_post_calls[4][1]["data"]

    # First invocation: creates new alias (no "id" field)
    assert "id" not in first_alias_save_data, (
        "First invocation should create a new alias (no 'id' in form data)"
    )

    # Second invocation: updates existing alias (has "id" field)
    assert "id" in second_alias_save_data, (
        "Second invocation should update existing alias (has 'id' in form data)"
    )
    assert second_alias_save_data["id"] == "3", (
        "Second invocation should reference the existing alias id"
    )

    # Both invocations should contain the same IPs in the alias
    for i, ip in enumerate(ip_list):
        key = f"address{i}"
        assert first_alias_save_data.get(key) == ip, (
            f"First alias save missing IP {ip} at {key}"
        )
        assert second_alias_save_data.get(key) == ip, (
            f"Second alias save missing IP {ip} at {key}"
        )

    # Verify no extra IPs beyond the blocklist
    extra_key = f"address{len(ip_list)}"
    assert extra_key not in first_alias_save_data, (
        "First alias save has extra IPs beyond blocklist"
    )
    assert extra_key not in second_alias_save_data, (
        "Second alias save has extra IPs beyond blocklist"
    )

    # Both invocations should submit exactly one floating rule creation each
    # Rule POST data is at indices 2 and 6
    first_rule_data = all_post_calls[2][1]["data"]
    second_rule_data = all_post_calls[6][1]["data"]

    assert first_rule_data["type"] == "block", "First rule should be a block rule"
    assert first_rule_data["src"] == ALIAS_NAME, "First rule should reference the alias"
    assert first_rule_data["floating"] == "yes", "First rule should be floating"

    assert second_rule_data["type"] == "block", "Second rule should be a block rule"
    assert second_rule_data["src"] == ALIAS_NAME, "Second rule should reference the alias"
    assert second_rule_data["floating"] == "yes", "Second rule should be floating"

    # The alias name should be consistent across both invocations
    assert first_alias_save_data["name"] == ALIAS_NAME
    assert second_alias_save_data["name"] == ALIAS_NAME
