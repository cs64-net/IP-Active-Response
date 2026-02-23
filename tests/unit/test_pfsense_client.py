"""Unit tests for pfSense client with mocked HTTP responses.

Tests CSRF token parsing, form submission, alias management,
null route operations, floating rule creation, health check,
and error handling.

Requirements: 3.2, 3.3, 9.1
"""

import pytest
import requests
from unittest.mock import patch, MagicMock, PropertyMock

from clients.pfsense_client import PfSenseClient, PfSenseError


# ---------------------------------------------------------------------------
# HTML helpers – simulate pfSense web interface responses
# ---------------------------------------------------------------------------

CSRF_TOKEN = "sid:abc123;csrf_magic_token_value"

LOGIN_PAGE_HTML = f"""
<html><body>
<form method="post">
<input name="__csrf_magic" value="{CSRF_TOKEN}" />
<input name="usernamefld" /><input name="passwordfld" />
<button name="login">Sign In</button>
</form></body></html>
"""

DASHBOARD_HTML = f"""
<html><body>
<input name="__csrf_magic" value="{CSRF_TOKEN}" />
<h1>pfSense Dashboard</h1>
</body></html>
"""

LOGIN_FAILED_HTML = f"""
<html><body>
<form method="post" action="/index.php">
<input name="__csrf_magic" value="{CSRF_TOKEN}" />
<input name="usernamefld" /><input name="passwordfld" />
<div class="alert">Username or Password incorrect</div>
</form></body></html>
"""

ROUTES_PAGE_HTML = f"""
<html><body>
<input name="__csrf_magic" value="{CSRF_TOKEN}" />
<table>
<tr><td>10.0.0.1/32</td><td>Null4</td>
<td><a href="system_routes.php?act=del&amp;id=5">Delete</a></td></tr>
</table></body></html>
"""

ROUTES_PAGE_MULTI_HTML = f"""
<html><body>
<input name="__csrf_magic" value="{CSRF_TOKEN}" />
<table>
<tr><td>10.0.0.1/32</td><td>Null4</td>
<td><a href="system_routes.php?act=del&amp;id=5">Delete</a></td></tr>
<tr><td>192.168.1.100/32</td><td>Null4</td>
<td><a href="system_routes.php?act=del&amp;id=7">Delete</a></td></tr>
</table></body></html>
"""

ROUTE_EDIT_HTML = f"""
<html><body>
<form method="post">
<input name="__csrf_magic" value="{CSRF_TOKEN}" />
</form></body></html>
"""

ALIASES_PAGE_HTML = f"""
<html><body>
<input name="__csrf_magic" value="{CSRF_TOKEN}" />
<table>
<tr><td><a href="firewall_aliases_edit.php?id=3">soc_blocklist</a></td></tr>
</table></body></html>
"""

ALIASES_PAGE_NO_MATCH_HTML = f"""
<html><body>
<input name="__csrf_magic" value="{CSRF_TOKEN}" />
<table><tr><td>No aliases</td></tr></table>
</body></html>
"""

ALIAS_EDIT_HTML = f"""
<html><body>
<form method="post">
<input name="__csrf_magic" value="{CSRF_TOKEN}" />
<input name="address0" value="10.0.0.1" />
<input name="address1" value="10.0.0.2" />
</form></body></html>
"""

FLOATING_RULE_EDIT_HTML = f"""
<html><body>
<form method="post">
<input name="__csrf_magic" value="{CSRF_TOKEN}" />
</form></body></html>
"""

FLOATING_RULES_PAGE_HTML = f"""
<html><body>
<input name="__csrf_magic" value="{CSRF_TOKEN}" />
<table></table></body></html>
"""

NO_CSRF_HTML = "<html><body><p>No token here</p></body></html>"


# ---------------------------------------------------------------------------
# Helper to build mock responses
# ---------------------------------------------------------------------------

def _mock_response(status_code=200, text="", url="https://fw/index.php"):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.text = text
    resp.url = url
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = requests.HTTPError(
            response=resp
        )
    return resp


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    """Create a PfSenseClient instance for testing."""
    return PfSenseClient(
        host="192.168.1.1",
        username="admin",
        password="pfsense",
        verify_ssl=False,
    )


@pytest.fixture
def logged_in_client(client):
    """Return a client with a pre-set session and CSRF token."""
    client.session = MagicMock(spec=requests.Session)
    client.session.verify = False
    client.csrf_token = CSRF_TOKEN
    return client


# ===========================================================================
# CSRF Token Parsing
# ===========================================================================

class TestCSRFTokenParsing:
    """Test _parse_csrf_token with various HTML patterns."""

    def test_parse_standard_csrf(self, client):
        html = '<input name="__csrf_magic" value="sid:token123" />'
        assert client._parse_csrf_token(html) == "sid:token123"

    def test_parse_csrf_reversed_attributes(self, client):
        html = '<input value="sid:reversed456" name="__csrf_magic" />'
        assert client._parse_csrf_token(html) == "sid:reversed456"

    def test_parse_csrf_single_quotes(self, client):
        html = "<input name='__csrf_magic' value='sid:single789' />"
        assert client._parse_csrf_token(html) == "sid:single789"

    def test_parse_csrf_missing_raises(self, client):
        with pytest.raises(PfSenseError, match="Failed to parse CSRF token"):
            client._parse_csrf_token(NO_CSRF_HTML)

    def test_parse_csrf_empty_html_raises(self, client):
        with pytest.raises(PfSenseError, match="Failed to parse CSRF token"):
            client._parse_csrf_token("")


# ===========================================================================
# Constructor / URL building
# ===========================================================================

class TestClientInit:

    def test_host_gets_https_prefix(self):
        c = PfSenseClient("10.0.0.1", "u", "p")
        assert c.host == "https://10.0.0.1"

    def test_host_preserves_existing_scheme(self):
        c = PfSenseClient("http://10.0.0.1", "u", "p")
        assert c.host == "http://10.0.0.1"

    def test_host_strips_trailing_slash(self):
        c = PfSenseClient("https://fw.local/", "u", "p")
        assert c.host == "https://fw.local"

    def test_get_url(self, client):
        assert client._get_url("/index.php") == "https://192.168.1.1/index.php"


# ===========================================================================
# Login
# ===========================================================================

class TestLogin:

    @patch("clients.pfsense_client.requests.Session")
    def test_successful_login(self, mock_session_cls, client):
        session = MagicMock()
        mock_session_cls.return_value = session

        session.get.return_value = _mock_response(text=LOGIN_PAGE_HTML)
        session.post.return_value = _mock_response(
            text=DASHBOARD_HTML, url="https://fw/dashboard"
        )

        result = client.login()
        assert result is session
        assert client.csrf_token == CSRF_TOKEN
        assert client.session is session

    @patch("clients.pfsense_client.requests.Session")
    def test_login_invalid_credentials(self, mock_session_cls, client):
        session = MagicMock()
        mock_session_cls.return_value = session

        session.get.return_value = _mock_response(text=LOGIN_PAGE_HTML)
        session.post.return_value = _mock_response(
            text=LOGIN_FAILED_HTML,
            url="https://fw/index.php?login=failed",
        )

        with pytest.raises(PfSenseError, match="invalid credentials"):
            client.login()

    @patch("clients.pfsense_client.requests.Session")
    def test_login_connection_error(self, mock_session_cls, client):
        session = MagicMock()
        mock_session_cls.return_value = session
        session.get.side_effect = requests.ConnectionError("refused")

        with pytest.raises(PfSenseError, match="Failed to connect"):
            client.login()

    @patch("clients.pfsense_client.requests.Session")
    def test_login_timeout(self, mock_session_cls, client):
        session = MagicMock()
        mock_session_cls.return_value = session
        session.get.side_effect = requests.Timeout("timed out")

        with pytest.raises(PfSenseError, match="Failed to connect"):
            client.login()

    @patch("clients.pfsense_client.requests.Session")
    def test_login_http_error(self, mock_session_cls, client):
        session = MagicMock()
        mock_session_cls.return_value = session
        session.get.return_value = _mock_response(status_code=503, text="")

        with pytest.raises(PfSenseError):
            client.login()


# ===========================================================================
# Null Route Operations
# ===========================================================================

class TestAddNullRoute:

    def test_add_null_route_success(self, logged_in_client):
        c = logged_in_client
        c.session.get.return_value = _mock_response(text=ROUTE_EDIT_HTML)
        c.session.post.return_value = _mock_response(text=ROUTE_EDIT_HTML)

        assert c.add_null_route("10.0.0.5") is True

        # Verify form submission included the IP and null gateway
        post_calls = c.session.post.call_args_list
        first_post_data = post_calls[0][1].get("data") or post_calls[0][0][1] if len(post_calls[0][0]) > 1 else post_calls[0][1]["data"]
        assert first_post_data["network"] == "10.0.0.5"
        assert first_post_data["gateway"] == "Null4"

    def test_add_null_route_connection_error(self, logged_in_client):
        c = logged_in_client
        c.session.get.side_effect = requests.ConnectionError("refused")

        with pytest.raises(PfSenseError, match="Failed to add null route"):
            c.add_null_route("10.0.0.5")

    def test_add_null_route_calls_ensure_session(self, client):
        """Verify _ensure_session triggers login when no session exists."""
        with patch.object(client, "login") as mock_login:
            mock_session = MagicMock()
            mock_session.get.return_value = _mock_response(text=ROUTE_EDIT_HTML)
            mock_session.post.return_value = _mock_response(text=ROUTE_EDIT_HTML)

            def set_session():
                client.session = mock_session
                client.csrf_token = CSRF_TOKEN
                return mock_session

            mock_login.side_effect = set_session
            client.add_null_route("10.0.0.1")
            mock_login.assert_called_once()


class TestRemoveNullRoute:

    def test_remove_null_route_success(self, logged_in_client):
        c = logged_in_client
        c.session.get.return_value = _mock_response(text=ROUTES_PAGE_HTML)
        c.session.post.return_value = _mock_response(text=ROUTES_PAGE_HTML)

        assert c.remove_null_route("10.0.0.1") is True

    def test_remove_null_route_not_found(self, logged_in_client):
        c = logged_in_client
        c.session.get.return_value = _mock_response(text=ROUTES_PAGE_HTML)

        with pytest.raises(PfSenseError, match="not found"):
            c.remove_null_route("99.99.99.99")

    def test_remove_null_route_finds_correct_id(self, logged_in_client):
        """When the IP appears in its own row with a delete link, the correct id is used."""
        c = logged_in_client
        # HTML where 192.168.1.100 appears before its delete link (second branch matches)
        html = f"""
        <html><body>
        <input name="__csrf_magic" value="{CSRF_TOKEN}" />
        <table>
        <tr><td>192.168.1.100/32</td><td>Null4</td>
        <td><a href="system_routes.php?act=del&amp;id=7">Delete</a></td></tr>
        </table></body></html>
        """
        c.session.get.return_value = _mock_response(text=html)
        c.session.post.return_value = _mock_response(text=html)

        c.remove_null_route("192.168.1.100")

        # The code does POST-based delete first; verify it used the correct route ID
        post_calls = c.session.post.call_args_list
        delete_data = post_calls[0][1]["data"]
        assert delete_data["act"] == "del"
        assert delete_data["id"] == "7"

    def test_remove_null_route_connection_error(self, logged_in_client):
        c = logged_in_client
        c.session.get.side_effect = requests.ConnectionError("refused")

        with pytest.raises(PfSenseError, match="Failed to remove null route"):
            c.remove_null_route("10.0.0.1")

    def test_remove_null_route_cidr(self, logged_in_client):
        """CIDR routes like 10.0.0.0/24 should be found and removed correctly."""
        c = logged_in_client
        html = f"""
        <html><body>
        <input name="__csrf_magic" value="{CSRF_TOKEN}" />
        <table>
        <tr><td>10.0.0.0/24</td><td>Null4</td>
        <td><a href="system_routes.php?act=del&amp;id=12">Delete</a></td></tr>
        </table></body></html>
        """
        c.session.get.return_value = _mock_response(text=html)
        c.session.post.return_value = _mock_response(text=html)

        assert c.remove_null_route("10.0.0.0/24") is True


# ===========================================================================
# Alias Management
# ===========================================================================

class TestEnsureAliasExists:

    def test_create_new_alias(self, logged_in_client):
        c = logged_in_client
        # First GET returns alias list with no match, second GET returns edit page
        c.session.get.side_effect = [
            _mock_response(text=ALIASES_PAGE_NO_MATCH_HTML),
            _mock_response(text=ALIAS_EDIT_HTML),
        ]
        c.session.post.side_effect = [
            _mock_response(text=ALIAS_EDIT_HTML),
            _mock_response(text=ALIASES_PAGE_NO_MATCH_HTML),
        ]

        assert c.ensure_alias_exists("soc_blocklist", ["10.0.0.1", "10.0.0.2"]) is True

        # Verify form data includes both IPs
        post_data = c.session.post.call_args_list[0][1]["data"]
        assert post_data["address0"] == "10.0.0.1/32"
        assert post_data["address1"] == "10.0.0.2/32"
        assert post_data["name"] == "soc_blocklist"
        assert "id" not in post_data  # New alias, no id

    def test_update_existing_alias(self, logged_in_client):
        c = logged_in_client
        c.session.get.side_effect = [
            _mock_response(text=ALIASES_PAGE_HTML),  # alias list with soc_blocklist id=3
            _mock_response(text=ALIAS_EDIT_HTML),
        ]
        c.session.post.side_effect = [
            _mock_response(text=ALIAS_EDIT_HTML),
            _mock_response(text=ALIASES_PAGE_HTML),
        ]

        assert c.ensure_alias_exists("soc_blocklist", ["10.0.0.1"]) is True

        post_data = c.session.post.call_args_list[0][1]["data"]
        assert post_data["id"] == "3"

    def test_ensure_alias_connection_error(self, logged_in_client):
        c = logged_in_client
        c.session.get.side_effect = requests.ConnectionError("refused")

        with pytest.raises(PfSenseError, match="Failed to ensure alias"):
            c.ensure_alias_exists("soc_blocklist", ["10.0.0.1"])


class TestAddIpToAlias:

    def test_add_ip_to_existing_alias(self, logged_in_client):
        c = logged_in_client
        c.session.get.side_effect = [
            _mock_response(text=ALIASES_PAGE_HTML),  # alias list
            _mock_response(text=ALIAS_EDIT_HTML),     # edit page with existing IPs
        ]
        c.session.post.side_effect = [
            _mock_response(text=ALIAS_EDIT_HTML),
            _mock_response(text=ALIASES_PAGE_HTML),
        ]

        assert c.add_ip_to_alias("soc_blocklist", "10.0.0.3") is True

        # Should include existing IPs + new one
        post_data = c.session.post.call_args_list[0][1]["data"]
        assert post_data["address0"] == "10.0.0.1/32"
        assert post_data["address1"] == "10.0.0.2/32"
        assert post_data["address2"] == "10.0.0.3/32"

    def test_add_ip_alias_not_found(self, logged_in_client):
        c = logged_in_client
        c.session.get.return_value = _mock_response(text=ALIASES_PAGE_NO_MATCH_HTML)

        with pytest.raises(PfSenseError, match="not found"):
            c.add_ip_to_alias("nonexistent", "10.0.0.1")

    def test_add_ip_to_alias_connection_error(self, logged_in_client):
        c = logged_in_client
        c.session.get.side_effect = requests.ConnectionError("refused")

        with pytest.raises(PfSenseError, match="Failed to add"):
            c.add_ip_to_alias("soc_blocklist", "10.0.0.1")

    def test_add_cidr_preserves_mask(self, logged_in_client):
        """Adding 10.0.0.0/24 should submit address=10.0.0.0 with subnet=24, not 32."""
        c = logged_in_client
        c.session.get.side_effect = [
            _mock_response(text=ALIASES_PAGE_HTML),
            _mock_response(text=ALIAS_EDIT_HTML),  # existing: 10.0.0.1, 10.0.0.2
        ]
        c.session.post.side_effect = [
            _mock_response(text=ALIAS_EDIT_HTML),
            _mock_response(text=ALIASES_PAGE_HTML),
        ]

        assert c.add_ip_to_alias("soc_blocklist", "10.0.0.0/24") is True

        post_data = c.session.post.call_args_list[0][1]["data"]
        # The new CIDR entry should be address2 with subnet 24
        assert post_data["address2"] == "10.0.0.0/24"
        assert post_data["address_subnet2"] == "24"

    def test_add_cidr_dedup(self, logged_in_client):
        """Adding 10.0.0.0/24 when 10.0.0.0 already exists should be a no-op."""
        c = logged_in_client
        alias_edit_with_addr = f"""
        <html><body>
        <form method="post">
        <input name="__csrf_magic" value="{CSRF_TOKEN}" />
        <input name="address0" value="10.0.0.0" />
        </form></body></html>
        """
        c.session.get.side_effect = [
            _mock_response(text=ALIASES_PAGE_HTML),
            _mock_response(text=alias_edit_with_addr),
        ]

        assert c.add_ip_to_alias("soc_blocklist", "10.0.0.0/24") is True
        # Should NOT have posted (dedup detected)
        assert c.session.post.call_count == 0


class TestRemoveIpFromAlias:

    def test_remove_ip_from_alias(self, logged_in_client):
        c = logged_in_client
        c.session.get.side_effect = [
            _mock_response(text=ALIASES_PAGE_HTML),
            _mock_response(text=ALIAS_EDIT_HTML),  # contains 10.0.0.1 and 10.0.0.2
        ]
        c.session.post.side_effect = [
            _mock_response(text=ALIAS_EDIT_HTML),
            _mock_response(text=ALIASES_PAGE_HTML),
        ]

        assert c.remove_ip_from_alias("soc_blocklist", "10.0.0.1") is True

        # Should only have 10.0.0.2 remaining
        post_data = c.session.post.call_args_list[0][1]["data"]
        assert post_data["address0"] == "10.0.0.2/32"
        assert "address1" not in post_data

    def test_remove_ip_not_in_alias(self, logged_in_client):
        c = logged_in_client
        c.session.get.side_effect = [
            _mock_response(text=ALIASES_PAGE_HTML),
            _mock_response(text=ALIAS_EDIT_HTML),
        ]

        with pytest.raises(PfSenseError, match="not found in alias"):
            c.remove_ip_from_alias("soc_blocklist", "99.99.99.99")

    def test_remove_ip_alias_not_found(self, logged_in_client):
        c = logged_in_client
        c.session.get.return_value = _mock_response(text=ALIASES_PAGE_NO_MATCH_HTML)

        with pytest.raises(PfSenseError, match="not found"):
            c.remove_ip_from_alias("nonexistent", "10.0.0.1")

    def test_remove_ip_from_alias_connection_error(self, logged_in_client):
        c = logged_in_client
        c.session.get.side_effect = requests.ConnectionError("refused")

        with pytest.raises(PfSenseError, match="Failed to remove"):
            c.remove_ip_from_alias("soc_blocklist", "10.0.0.1")

    def test_remove_cidr_from_alias(self, logged_in_client):
        """CIDR entries like 10.0.0.0/24 are stored as address=10.0.0.0 in pfSense forms."""
        c = logged_in_client
        alias_edit_with_cidr = f"""
        <html><body>
        <form method="post">
        <input name="__csrf_magic" value="{CSRF_TOKEN}" />
        <input name="address0" value="10.0.0.0" />
        <input name="address1" value="192.168.1.1" />
        </form></body></html>
        """
        c.session.get.side_effect = [
            _mock_response(text=ALIASES_PAGE_HTML),
            _mock_response(text=alias_edit_with_cidr),
        ]
        c.session.post.side_effect = [
            _mock_response(text=alias_edit_with_cidr),
            _mock_response(text=ALIASES_PAGE_HTML),
        ]

        # Pass CIDR notation — should match the address part "10.0.0.0"
        assert c.remove_ip_from_alias("soc_blocklist", "10.0.0.0/24") is True

        post_data = c.session.post.call_args_list[0][1]["data"]
        assert post_data["address0"] == "192.168.1.1/32"
        assert "address1" not in post_data


# ===========================================================================
# Floating Rule
# ===========================================================================

class TestCreateFloatingRule:

    def test_create_floating_rule_success(self, logged_in_client):
        c = logged_in_client
        c.session.get.side_effect = [
            _mock_response(text=FLOATING_RULES_PAGE_HTML),   # check existing rules
            _mock_response(text=FLOATING_RULE_EDIT_HTML),    # GET edit page for inbound rule
            _mock_response(text=FLOATING_RULE_EDIT_HTML),    # GET edit page for outbound rule
            _mock_response(text=FLOATING_RULES_PAGE_HTML),   # GET floating page before apply
        ]
        c.session.post.side_effect = [
            _mock_response(text=FLOATING_RULE_EDIT_HTML),    # POST inbound rule
            _mock_response(text=FLOATING_RULE_EDIT_HTML),    # POST outbound rule
            _mock_response(text=FLOATING_RULES_PAGE_HTML),   # POST apply changes
        ]

        assert c.create_floating_rule("soc_blocklist") is True

        # First POST is the inbound rule
        post_data = c.session.post.call_args_list[0][1]["data"]
        assert post_data["type"] == "block"
        assert post_data["src"] == "soc_blocklist"
        assert post_data["srctype"] == "single"
        assert "srcmask" not in post_data
        assert post_data["dsttype"] == "any"
        assert post_data["ipprotocol"] == "inet"
        assert post_data["floating"] == "yes"
        assert post_data["quick"] == "yes"
        assert post_data["interface[]"] == ["any"]
        assert "srcbeginport" not in post_data
        assert "srcendport" not in post_data
        assert "dstbeginport" not in post_data
        assert "dstendport" not in post_data

        # Second POST is the outbound rule
        out_data = c.session.post.call_args_list[1][1]["data"]
        assert out_data["type"] == "block"
        assert out_data["dst"] == "soc_blocklist"
        assert out_data["dsttype"] == "single"
        assert "dstmask" not in out_data
        assert out_data["srctype"] == "any"
        assert out_data["ipprotocol"] == "inet"
        assert out_data["floating"] == "yes"
        assert out_data["quick"] == "yes"
        assert "dstbeginport" not in out_data
        assert "dstendport" not in out_data
        assert "srcbeginport" not in out_data
        assert "srcendport" not in out_data

    def test_create_floating_rule_connection_error(self, logged_in_client):
        c = logged_in_client
        c.session.get.side_effect = requests.ConnectionError("refused")

        with pytest.raises(PfSenseError, match="Failed to create floating rule"):
            c.create_floating_rule("soc_blocklist")


# ===========================================================================
# Health Check
# ===========================================================================

class TestCheckHealth:

    @patch("clients.pfsense_client.requests.Session")
    def test_health_check_success(self, mock_session_cls, client):
        session = MagicMock()
        mock_session_cls.return_value = session
        session.get.return_value = _mock_response(status_code=200)

        assert client.check_health() is True

    @patch("clients.pfsense_client.requests.Session")
    def test_health_check_non_200(self, mock_session_cls, client):
        session = MagicMock()
        mock_session_cls.return_value = session
        resp = MagicMock(spec=requests.Response)
        resp.status_code = 503
        session.get.return_value = resp

        assert client.check_health() is False

    @patch("clients.pfsense_client.requests.Session")
    def test_health_check_connection_error(self, mock_session_cls, client):
        session = MagicMock()
        mock_session_cls.return_value = session
        session.get.side_effect = requests.ConnectionError("refused")

        assert client.check_health() is False

    @patch("clients.pfsense_client.requests.Session")
    def test_health_check_timeout(self, mock_session_cls, client):
        session = MagicMock()
        mock_session_cls.return_value = session
        session.get.side_effect = requests.Timeout("timed out")

        assert client.check_health() is False


# ===========================================================================
# Error Handling & Logging (Req 9.1)
# ===========================================================================

class TestErrorHandling:

    def test_pfsense_error_includes_host(self, logged_in_client):
        """Errors should include the device identifier (host) for logging."""
        c = logged_in_client
        c.session.get.side_effect = requests.ConnectionError("connection refused")

        with pytest.raises(PfSenseError) as exc_info:
            c.add_null_route("10.0.0.1")
        assert "192.168.1.1" in str(exc_info.value)

    def test_pfsense_error_includes_ip(self, logged_in_client):
        c = logged_in_client
        c.session.get.side_effect = requests.ConnectionError("connection refused")

        with pytest.raises(PfSenseError) as exc_info:
            c.add_null_route("10.0.0.5")
        assert "10.0.0.5" in str(exc_info.value)

    def test_pfsense_error_wraps_original_exception(self, logged_in_client):
        c = logged_in_client
        original = requests.ConnectionError("original error")
        c.session.get.side_effect = original

        with pytest.raises(PfSenseError) as exc_info:
            c.add_null_route("10.0.0.1")
        assert exc_info.value.__cause__ is original

    def test_remove_null_route_error_includes_context(self, logged_in_client):
        c = logged_in_client
        c.session.get.side_effect = requests.Timeout("timed out")

        with pytest.raises(PfSenseError) as exc_info:
            c.remove_null_route("10.0.0.1")
        assert "192.168.1.1" in str(exc_info.value)
        assert "10.0.0.1" in str(exc_info.value)

    def test_alias_error_includes_alias_name(self, logged_in_client):
        c = logged_in_client
        c.session.get.side_effect = requests.ConnectionError("refused")

        with pytest.raises(PfSenseError) as exc_info:
            c.ensure_alias_exists("my_alias", ["10.0.0.1"])
        assert "my_alias" in str(exc_info.value)

    def test_floating_rule_error_includes_alias_name(self, logged_in_client):
        c = logged_in_client
        c.session.get.side_effect = requests.ConnectionError("refused")

        with pytest.raises(PfSenseError) as exc_info:
            c.create_floating_rule("soc_blocklist")
        assert "soc_blocklist" in str(exc_info.value)


class TestSplitIpMask:
    def test_plain_ip(self):
        assert PfSenseClient._split_ip_mask("10.0.0.1") == ("10.0.0.1", "32")

    def test_cidr_24(self):
        assert PfSenseClient._split_ip_mask("10.0.0.0/24") == ("10.0.0.0", "24")

    def test_cidr_16(self):
        assert PfSenseClient._split_ip_mask("172.16.0.0/16") == ("172.16.0.0", "16")

    def test_ipv6_plain(self):
        assert PfSenseClient._split_ip_mask("2001:db8::1") == ("2001:db8::1", "32")

    def test_ipv6_cidr(self):
        assert PfSenseClient._split_ip_mask("2001:db8::/48") == ("2001:db8::", "48")
