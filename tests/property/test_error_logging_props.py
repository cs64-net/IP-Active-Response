# Feature: soc-ip-blocker, Property 18: Error logging contains required details
"""Property-based tests for error logging details.

Validates that for any failed device operation (pfSense web interface error
or SSH failure), the error log entry contains the device identifier,
error details, and a timestamp.

**Validates: Requirements 9.1, 9.2**
"""

import logging
import re
from unittest.mock import patch, MagicMock

import requests as requests_lib

from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from clients.pfsense_client import PfSenseClient, PfSenseError
from clients.linux_client import LinuxClient, LinuxClientError


# --- Strategies ---

hostname_strategy = st.from_regex(r"[a-z][a-z0-9]{1,12}\.[a-z]{2,4}", fullmatch=True)

ip_strategy = st.tuples(
    st.integers(1, 254),
    st.integers(0, 255),
    st.integers(0, 255),
    st.integers(1, 254),
).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}")

error_message_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=50,
)

http_status_strategy = st.sampled_from([400, 401, 403, 404, 500, 502, 503])


# --- Helpers ---

LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")


class _LogCapture(logging.Handler):
    """Logging handler that captures formatted records with timestamps."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.setFormatter(logging.Formatter(LOG_FORMAT))
        self.records_text: list = []

    def emit(self, record):
        self.records_text.append(self.format(record))

    def output(self) -> str:
        return "\n".join(self.records_text)


# --- Property 18: Error logging contains required details ---


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    hostname=hostname_strategy,
    ip_addr=ip_strategy,
    error_msg=error_message_strategy,
    http_status=http_status_strategy,
)
def test_pfsense_error_logging_contains_required_details(
    hostname, ip_addr, error_msg, http_status
):
    """**Validates: Requirements 9.1**

    For any failed pfSense web interface operation, the error log entry
    should contain the device identifier (hostname), error details
    (HTTP status code), and a timestamp.
    """
    # Capture logs from the push engine logger (where errors are logged)
    push_logger = logging.getLogger("services.push_engine")
    capture = _LogCapture()
    push_logger.addHandler(capture)
    push_logger.setLevel(logging.DEBUG)

    try:
        client = PfSenseClient(
            host=hostname,
            username="admin",
            password="password",
            verify_ssl=False,
        )

        # Mock the session so HTTP calls raise a RequestException
        mock_session = MagicMock(spec=requests_lib.Session)
        conn_error = requests_lib.ConnectionError(
            f"{http_status} {error_msg}"
        )
        mock_session.get.side_effect = conn_error
        mock_session.post.side_effect = conn_error
        mock_session.verify = False

        client.session = mock_session
        client.csrf_token = "fake-csrf"

        # Build a device dict as the push engine would see it
        device = {
            "id": 1,
            "hostname": hostname,
            "device_type": "pfsense",
            "web_username": "admin",
            "web_password": "password",
            "block_method": "null_route",
        }

        # Use the real push engine _push_to_device method
        from services.push_engine import PushEngine
        engine = PushEngine()

        # Patch PfSenseClient construction to return our pre-configured client
        with patch("services.push_engine.PfSenseClient", return_value=client):
            result = engine._push_to_device(ip_addr, device, "block")

        # The push should have failed
        assert result["success"] is False, "Expected push to fail"

        log_text = capture.output()

        # 1. Log contains a timestamp (from the formatter)
        assert TIMESTAMP_PATTERN.search(log_text), (
            f"Log should contain a timestamp, got: {log_text[:300]}"
        )

        # 2. Log contains the device identifier (hostname)
        assert hostname in log_text, (
            f"Log should contain device hostname '{hostname}', "
            f"got: {log_text[:300]}"
        )

        # 3. Log contains error details (HTTP status code or error info)
        assert str(http_status) in log_text or error_msg in log_text, (
            f"Log should contain error details (status={http_status} or msg), "
            f"got: {log_text[:300]}"
        )

    finally:
        push_logger.removeHandler(capture)


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    hostname=hostname_strategy,
    ip_addr=ip_strategy,
    error_output=error_message_strategy,
)
def test_linux_error_logging_contains_required_details(
    hostname, ip_addr, error_output
):
    """**Validates: Requirements 9.2**

    For any failed SSH command on a Linux device, the error log entry
    should contain the device identifier (hostname), error details
    (error output), and a timestamp.
    """
    # Capture logs from the push engine logger
    push_logger = logging.getLogger("services.push_engine")
    capture = _LogCapture()
    push_logger.addHandler(capture)
    push_logger.setLevel(logging.DEBUG)

    try:
        # Build a device dict as the push engine would see it
        device = {
            "id": 1,
            "hostname": hostname,
            "device_type": "linux",
            "ssh_port": 22,
            "ssh_username": "root",
            "ssh_password": "password",
            "ssh_key_path": None,
        }

        from services.push_engine import PushEngine
        engine = PushEngine()

        # Create a LinuxClient that fails with the generated error output
        mock_client = MagicMock(spec=LinuxClient)
        mock_client.add_null_route.side_effect = LinuxClientError(
            f"Failed to add null route for {ip_addr} on {hostname}: {error_output}"
        )

        with patch("services.push_engine.LinuxClient", return_value=mock_client):
            result = engine._push_to_device(ip_addr, device, "block")

        # The push should have failed
        assert result["success"] is False, "Expected push to fail"

        log_text = capture.output()

        # 1. Log contains a timestamp (from the formatter)
        assert TIMESTAMP_PATTERN.search(log_text), (
            f"Log should contain a timestamp, got: {log_text[:300]}"
        )

        # 2. Log contains the device identifier (hostname)
        assert hostname in log_text, (
            f"Log should contain device hostname '{hostname}', "
            f"got: {log_text[:300]}"
        )

        # 3. Log contains error details (error output)
        assert error_output in log_text or ip_addr in log_text, (
            f"Log should contain error details, "
            f"got: {log_text[:300]}"
        )

    finally:
        push_logger.removeHandler(capture)
