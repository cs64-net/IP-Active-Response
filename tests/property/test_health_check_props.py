# Feature: soc-ip-blocker, Property 17: Health check status mapping
"""Property-based tests for health check status mapping.

Validates that StatusMonitor.check_device() correctly maps health check
results to "online" (success) or "offline" (failure) for both pfSense
and Linux device types.
"""

import os
import tempfile
from unittest.mock import patch, MagicMock

from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from database import init_db, get_db
from services.status_monitor import StatusMonitor


# --- Strategies ---

pfsense_device_strategy = st.fixed_dictionaries({
    "id": st.integers(min_value=1, max_value=10000),
    "hostname": st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789.", min_size=3, max_size=15),
    "device_type": st.just("pfsense"),
    "web_username": st.just("admin"),
    "web_password": st.just("password"),
    "block_method": st.sampled_from(["null_route", "floating_rule"]),
})

linux_device_strategy = st.fixed_dictionaries({
    "id": st.integers(min_value=1, max_value=10000),
    "hostname": st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789.", min_size=3, max_size=15),
    "device_type": st.just("linux"),
    "ssh_port": st.integers(min_value=1, max_value=65535),
    "ssh_username": st.just("root"),
    "ssh_password": st.just("password"),
    "ssh_key_path": st.none(),
})

device_strategy = st.one_of(pfsense_device_strategy, linux_device_strategy)

health_result_strategy = st.booleans()


# --- Property 17: Health check status mapping ---


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(device=device_strategy, health_success=health_result_strategy)
def test_health_check_status_mapping(device: dict, health_success: bool):
    """**Validates: Requirements 8.2, 8.3, 8.4, 8.5**

    For any managed device, if the health check succeeds the status should
    be "online", and if it fails the status should be "offline".
    """
    monitor = StatusMonitor()

    with patch("services.status_monitor.PfSenseClient") as mock_pf_cls, \
         patch("services.status_monitor.LinuxClient") as mock_lx_cls:

        mock_pf_instance = MagicMock()
        mock_pf_instance.check_health.return_value = health_success
        mock_pf_cls.return_value = mock_pf_instance

        mock_lx_instance = MagicMock()
        mock_lx_instance.check_health.return_value = health_success
        mock_lx_cls.return_value = mock_lx_instance

        status = monitor.check_device(device)

    expected = "online" if health_success else "offline"
    assert status == expected, (
        f"Device type={device['device_type']}, health={health_success}: "
        f"expected '{expected}', got '{status}'"
    )
