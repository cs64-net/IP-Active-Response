"""Unit tests for Linux client with mocked SSH (paramiko).

Tests SSH command construction, connection error handling,
health check functionality, and error message content.

Requirements: 4.1, 4.2, 9.2
"""

import pytest
import paramiko
from unittest.mock import patch, MagicMock, PropertyMock, call

from clients.linux_client import LinuxClient, LinuxClientError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    """Create a LinuxClient with password auth (sudo_password defaults to password)."""
    return LinuxClient(
        host="192.168.1.50",
        port=22,
        username="root",
        password="secret",
    )


@pytest.fixture
def key_client():
    """Create a LinuxClient with key-based auth."""
    return LinuxClient(
        host="10.0.0.10",
        port=2222,
        username="admin",
        key_path="/home/admin/.ssh/id_rsa",
    )


def _mock_ssh_client_multi(exec_results):
    """Build a mock paramiko.SSHClient that returns different results per exec_command call.

    Args:
        exec_results: list of (exit_status, stdout_output, stderr_output) tuples.
    """
    mock_client = MagicMock()
    side_effects = []
    for exit_status, stdout_output, stderr_output in exec_results:
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_stdout.channel.recv_exit_status.return_value = exit_status
        mock_stdout.read.return_value = stdout_output.encode()
        mock_stderr.read.return_value = stderr_output.encode()
        side_effects.append((mock_stdin, mock_stdout, mock_stderr))
    mock_client.exec_command.side_effect = side_effects
    return mock_client


def _mock_ssh_client(exit_status=0, stderr_output="", stdout_output=""):
    """Build a mock paramiko.SSHClient with configurable exec_command results.

    This returns the same result for every exec_command call.
    """
    mock_client = MagicMock()

    def make_result():
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_stdout.channel.recv_exit_status.return_value = exit_status
        mock_stdout.read.return_value = stdout_output.encode()
        mock_stderr.read.return_value = stderr_output.encode()
        return (mock_stdin, mock_stdout, mock_stderr)

    mock_client.exec_command.side_effect = lambda cmd: make_result()
    return mock_client


# ===========================================================================
# Constructor
# ===========================================================================

class TestClientInit:

    def test_password_auth_params(self):
        c = LinuxClient("host1", 22, "user", password="pass")
        assert c.host == "host1"
        assert c.port == 22
        assert c.username == "user"
        assert c.password == "pass"
        assert c.key_path is None
        # sudo_password defaults to password
        assert c.sudo_password == "pass"

    def test_key_auth_params(self):
        c = LinuxClient("host2", 2222, "admin", key_path="/keys/id_rsa")
        assert c.host == "host2"
        assert c.port == 2222
        assert c.username == "admin"
        assert c.password is None
        assert c.key_path == "/keys/id_rsa"

    def test_sudo_password_override(self):
        c = LinuxClient("host1", 22, "user", password="pass", sudo_password="sudopass")
        assert c.sudo_password == "sudopass"
        assert c.password == "pass"


# ===========================================================================
# SSH Connection (_get_ssh_client)
# ===========================================================================

class TestSSHConnection:

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_connect_with_password(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance

        result = client._get_ssh_client()

        mock_instance.set_missing_host_key_policy.assert_called_once()
        mock_instance.connect.assert_called_once_with(
            hostname="192.168.1.50",
            port=22,
            username="root",
            timeout=10,
            password="secret",
        )
        assert result is mock_instance

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_connect_with_key(self, mock_ssh_cls, key_client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance

        result = key_client._get_ssh_client()

        mock_instance.connect.assert_called_once_with(
            hostname="10.0.0.10",
            port=2222,
            username="admin",
            timeout=10,
            key_filename="/home/admin/.ssh/id_rsa",
        )
        assert result is mock_instance

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_auto_add_host_key_policy(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance

        client._get_ssh_client()

        args = mock_instance.set_missing_host_key_policy.call_args[0]
        assert isinstance(args[0], paramiko.AutoAddPolicy)


# ===========================================================================
# Add Null Route (Req 4.1) — now with sudo + dedup
# ===========================================================================

class TestAddNullRoute:

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_add_null_route_success(self, mock_ssh_cls, client):
        """Route doesn't exist yet → check route (no blackhole) then add."""
        mock_instance = _mock_ssh_client_multi([
            # _route_exists: ip route show → no blackhole
            (0, "", ""),
            # add blackhole
            (0, "", ""),
        ])
        mock_ssh_cls.return_value = mock_instance

        result = client.add_null_route("10.0.0.5")

        assert result is True
        calls = mock_instance.exec_command.call_args_list
        assert len(calls) == 2
        assert "ip route show 10.0.0.5" in calls[0][0][0]
        assert "ip route add blackhole 10.0.0.5" in calls[1][0][0]
        mock_instance.close.assert_called_once()

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_add_null_route_already_exists(self, mock_ssh_cls, client):
        """Route already exists → _route_exists returns True, skip add."""
        mock_instance = _mock_ssh_client_multi([
            # _route_exists: ip route show → blackhole found
            (0, "blackhole 10.0.0.5", ""),
        ])
        mock_ssh_cls.return_value = mock_instance

        result = client.add_null_route("10.0.0.5")

        assert result is True
        # Only one call (the route check), no add
        assert mock_instance.exec_command.call_count == 1
        mock_instance.close.assert_called_once()

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_add_null_route_file_exists_idempotent(self, mock_ssh_cls, client):
        """'File exists' error is treated as success (idempotent)."""
        mock_instance = _mock_ssh_client_multi([
            # _route_exists: no blackhole
            (0, "", ""),
            # add blackhole → File exists
            (2, "", "RTNETLINK answers: File exists"),
        ])
        mock_ssh_cls.return_value = mock_instance

        result = client.add_null_route("10.0.0.5")
        assert result is True

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_add_null_route_ipv6(self, mock_ssh_cls, client):
        mock_instance = _mock_ssh_client_multi([
            (0, "", ""),
            (0, "", ""),
        ])
        mock_ssh_cls.return_value = mock_instance

        result = client.add_null_route("2001:db8::1")

        assert result is True
        calls = mock_instance.exec_command.call_args_list
        assert "2001:db8::1" in calls[1][0][0]

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_add_null_route_real_error(self, mock_ssh_cls, client):
        """Non-'File exists' error raises LinuxClientError."""
        mock_instance = _mock_ssh_client_multi([
            (0, "", ""),
            (2, "", "RTNETLINK: Network unreachable"),
        ])
        mock_ssh_cls.return_value = mock_instance

        with pytest.raises(LinuxClientError, match="Failed to add null route"):
            client.add_null_route("10.0.0.5")
        mock_instance.close.assert_called_once()

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_add_null_route_closes_client_on_success(self, mock_ssh_cls, client):
        mock_instance = _mock_ssh_client_multi([
            (0, "", ""),
            (0, "", ""),
        ])
        mock_ssh_cls.return_value = mock_instance

        client.add_null_route("10.0.0.1")
        mock_instance.close.assert_called_once()

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_add_null_route_closes_client_on_failure(self, mock_ssh_cls, client):
        mock_instance = _mock_ssh_client_multi([
            (0, "", ""),
            (1, "", "some real error"),
        ])
        mock_ssh_cls.return_value = mock_instance

        with pytest.raises(LinuxClientError):
            client.add_null_route("10.0.0.1")
        mock_instance.close.assert_called_once()

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_add_uses_sudo(self, mock_ssh_cls, client):
        """When sudo_password is set, commands are prefixed with sudo -S."""
        mock_instance = _mock_ssh_client_multi([
            (0, "", ""),
            (0, "", ""),
        ])
        mock_ssh_cls.return_value = mock_instance

        client.add_null_route("10.0.0.5")

        calls = mock_instance.exec_command.call_args_list
        assert calls[0][0][0].startswith("sudo -S ")
        assert calls[1][0][0].startswith("sudo -S ")


# ===========================================================================
# Remove Null Route (Req 4.2) — now with sudo + idempotent
# ===========================================================================

class TestRemoveNullRoute:

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_remove_null_route_success(self, mock_ssh_cls, client):
        """Route exists → check then remove."""
        mock_instance = _mock_ssh_client_multi([
            # _route_exists: blackhole found
            (0, "blackhole 10.0.0.5", ""),
            # del blackhole
            (0, "", ""),
        ])
        mock_ssh_cls.return_value = mock_instance

        result = client.remove_null_route("10.0.0.5")

        assert result is True
        calls = mock_instance.exec_command.call_args_list
        assert len(calls) == 2
        assert "ip route show 10.0.0.5" in calls[0][0][0]
        assert "ip route del blackhole 10.0.0.5" in calls[1][0][0]
        mock_instance.close.assert_called_once()

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_remove_null_route_not_exists(self, mock_ssh_cls, client):
        """Route doesn't exist → returns True without trying to remove."""
        mock_instance = _mock_ssh_client_multi([
            (0, "", ""),
        ])
        mock_ssh_cls.return_value = mock_instance

        result = client.remove_null_route("10.0.0.5")

        assert result is True
        assert mock_instance.exec_command.call_count == 1
        mock_instance.close.assert_called_once()

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_remove_null_route_no_such_process_idempotent(self, mock_ssh_cls, client):
        """'No such process' error is treated as success (idempotent)."""
        mock_instance = _mock_ssh_client_multi([
            (0, "blackhole 10.0.0.5", ""),
            (2, "", "RTNETLINK answers: No such process"),
        ])
        mock_ssh_cls.return_value = mock_instance

        result = client.remove_null_route("10.0.0.5")
        assert result is True

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_remove_null_route_ipv6(self, mock_ssh_cls, client):
        mock_instance = _mock_ssh_client_multi([
            (0, "blackhole fd00::1", ""),
            (0, "", ""),
        ])
        mock_ssh_cls.return_value = mock_instance

        result = client.remove_null_route("fd00::1")

        assert result is True
        calls = mock_instance.exec_command.call_args_list
        assert "fd00::1" in calls[1][0][0]

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_remove_null_route_real_error(self, mock_ssh_cls, client):
        """Non-'No such process' error raises LinuxClientError."""
        mock_instance = _mock_ssh_client_multi([
            (0, "blackhole 10.0.0.5", ""),
            (2, "", "RTNETLINK: Operation not permitted"),
        ])
        mock_ssh_cls.return_value = mock_instance

        with pytest.raises(LinuxClientError, match="Failed to remove null route"):
            client.remove_null_route("10.0.0.5")
        mock_instance.close.assert_called_once()

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_remove_null_route_closes_client_on_success(self, mock_ssh_cls, client):
        mock_instance = _mock_ssh_client_multi([
            (0, "blackhole 10.0.0.1", ""),
            (0, "", ""),
        ])
        mock_ssh_cls.return_value = mock_instance

        client.remove_null_route("10.0.0.1")
        mock_instance.close.assert_called_once()


# ===========================================================================
# Bulk Operations
# ===========================================================================

class TestBulkOperations:

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_add_bulk_empty_list(self, mock_ssh_cls, client):
        result = client.add_null_routes_bulk([])
        assert result == {"success": [], "failed": []}

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_add_bulk_success(self, mock_ssh_cls, client):
        mock_instance = _mock_ssh_client(exit_status=0, stdout_output="")
        mock_ssh_cls.return_value = mock_instance

        result = client.add_null_routes_bulk(["10.0.0.1", "10.0.0.2"])
        assert len(result["success"]) == 2
        assert len(result["failed"]) == 0

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_remove_bulk_empty_list(self, mock_ssh_cls, client):
        result = client.remove_null_routes_bulk([])
        assert result == {"success": [], "failed": []}

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_add_bulk_connection_failure(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance
        mock_instance.connect.side_effect = OSError("Connection refused")

        result = client.add_null_routes_bulk(["10.0.0.1", "10.0.0.2"])
        assert len(result["success"]) == 0
        assert len(result["failed"]) == 2

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_remove_bulk_connection_failure(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance
        mock_instance.connect.side_effect = OSError("Connection refused")

        result = client.remove_null_routes_bulk(["10.0.0.1"])
        assert len(result["success"]) == 0
        assert len(result["failed"]) == 1


# ===========================================================================
# Connection Error Handling (Req 4.3, 9.2)
# ===========================================================================

class TestConnectionErrors:

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_auth_failure_add(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance
        mock_instance.connect.side_effect = paramiko.AuthenticationException("Auth failed")

        with pytest.raises(LinuxClientError, match="SSH error adding null route"):
            client.add_null_route("10.0.0.1")

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_auth_failure_remove(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance
        mock_instance.connect.side_effect = paramiko.AuthenticationException("Auth failed")

        with pytest.raises(LinuxClientError, match="SSH error removing null route"):
            client.remove_null_route("10.0.0.1")

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_connection_refused_add(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance
        mock_instance.connect.side_effect = OSError("Connection refused")

        with pytest.raises(LinuxClientError, match="SSH error adding null route"):
            client.add_null_route("10.0.0.1")

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_connection_refused_remove(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance
        mock_instance.connect.side_effect = OSError("Connection refused")

        with pytest.raises(LinuxClientError, match="SSH error removing null route"):
            client.remove_null_route("10.0.0.1")

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_timeout_add(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance
        mock_instance.connect.side_effect = TimeoutError("Connection timed out")

        with pytest.raises(LinuxClientError, match="SSH error adding null route"):
            client.add_null_route("10.0.0.1")

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_timeout_remove(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance
        mock_instance.connect.side_effect = TimeoutError("Connection timed out")

        with pytest.raises(LinuxClientError, match="SSH error removing null route"):
            client.remove_null_route("10.0.0.1")

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_ssh_exception_add(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance
        mock_instance.connect.side_effect = paramiko.SSHException("SSH protocol error")

        with pytest.raises(LinuxClientError, match="SSH error adding null route"):
            client.add_null_route("10.0.0.1")


# ===========================================================================
# Health Check (Req 8.4, 8.5)
# ===========================================================================

class TestCheckHealth:

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_health_check_success(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance

        assert client.check_health() is True
        mock_instance.connect.assert_called_once()
        mock_instance.close.assert_called_once()

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_health_check_auth_failure(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance
        mock_instance.connect.side_effect = paramiko.AuthenticationException("bad key")

        assert client.check_health() is False

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_health_check_connection_refused(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance
        mock_instance.connect.side_effect = OSError("Connection refused")

        assert client.check_health() is False

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_health_check_timeout(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance
        mock_instance.connect.side_effect = TimeoutError("timed out")

        assert client.check_health() is False

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_health_check_ssh_exception(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance
        mock_instance.connect.side_effect = paramiko.SSHException("protocol error")

        assert client.check_health() is False


# ===========================================================================
# Error Message Content (Req 9.2)
# ===========================================================================

class TestErrorMessages:
    """Verify error messages include device identifier and error details."""

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_add_error_includes_host(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance
        mock_instance.connect.side_effect = OSError("refused")

        with pytest.raises(LinuxClientError) as exc_info:
            client.add_null_route("10.0.0.1")
        assert "192.168.1.50" in str(exc_info.value)

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_add_error_includes_ip(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance
        mock_instance.connect.side_effect = OSError("refused")

        with pytest.raises(LinuxClientError) as exc_info:
            client.add_null_route("10.0.0.5")
        assert "10.0.0.5" in str(exc_info.value)

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_remove_error_includes_host(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance
        mock_instance.connect.side_effect = OSError("refused")

        with pytest.raises(LinuxClientError) as exc_info:
            client.remove_null_route("10.0.0.1")
        assert "192.168.1.50" in str(exc_info.value)

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_remove_error_includes_ip(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance
        mock_instance.connect.side_effect = OSError("refused")

        with pytest.raises(LinuxClientError) as exc_info:
            client.remove_null_route("10.0.0.5")
        assert "10.0.0.5" in str(exc_info.value)

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_add_error_wraps_original_exception(self, mock_ssh_cls, client):
        mock_instance = MagicMock()
        mock_ssh_cls.return_value = mock_instance
        original = paramiko.AuthenticationException("bad credentials")
        mock_instance.connect.side_effect = original

        with pytest.raises(LinuxClientError) as exc_info:
            client.add_null_route("10.0.0.1")
        assert exc_info.value.__cause__ is original

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_command_failure_includes_stderr(self, mock_ssh_cls, client):
        """Real error (not 'File exists') includes stderr in exception."""
        mock_instance = _mock_ssh_client_multi([
            (0, "", ""),  # route check
            (1, "", "RTNETLINK: Network unreachable"),  # add fails
        ])
        mock_ssh_cls.return_value = mock_instance

        with pytest.raises(LinuxClientError) as exc_info:
            client.add_null_route("10.0.0.1")
        assert "RTNETLINK: Network unreachable" in str(exc_info.value)

    @patch("clients.linux_client.paramiko.SSHClient")
    def test_remove_command_failure_includes_stderr(self, mock_ssh_cls, client):
        """Real error (not 'No such process') includes stderr in exception."""
        mock_instance = _mock_ssh_client_multi([
            (0, "blackhole 10.0.0.1", ""),  # route exists
            (2, "", "RTNETLINK: Operation not permitted"),  # del fails
        ])
        mock_ssh_cls.return_value = mock_instance

        with pytest.raises(LinuxClientError) as exc_info:
            client.remove_null_route("10.0.0.1")
        assert "Operation not permitted" in str(exc_info.value)
