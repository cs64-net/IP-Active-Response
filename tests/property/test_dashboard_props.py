# Feature: soc-ip-blocker, Property 16: Dashboard summary counts are correct
"""Property-based tests for dashboard summary counts."""

import ipaddress
import os
import re
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

device_status_strategy = st.sampled_from(["online", "offline", "unknown"])

device_type_strategy = st.sampled_from(["pfsense", "linux"])

hostname_strategy = st.tuples(
    st.integers(min_value=1, max_value=254),
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=1, max_value=254),
).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}")

# Strategy for a single device: (hostname, device_type, status)
device_entry_strategy = st.tuples(hostname_strategy, device_type_strategy, device_status_strategy)

# Strategy for a list of unique IPs (0 to 10)
ip_list_strategy = st.lists(
    ipv4_strategy,
    min_size=0,
    max_size=10,
    unique_by=lambda ip: str(ipaddress.ip_address(ip)),
)

# Strategy for a list of devices (0 to 10)
device_list_strategy = st.lists(device_entry_strategy, min_size=0, max_size=10)


def fresh_db():
    """Create a fresh temporary database and return its path."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    return path


def create_test_app(db_path):
    """Create a minimal Flask app wired to the given database."""
    from flask import Flask
    from routes.dashboard_routes import dashboard_bp
    from routes.auth_routes import auth_bp
    from routes.blocklist_routes import blocklist_bp
    from routes.settings_routes import settings_bp

    app = Flask(__name__, template_folder=os.path.join(
        os.path.dirname(__file__), "..", "..", "templates"
    ))
    app.secret_key = "test-secret"
    app.config["TESTING"] = True

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(blocklist_bp)
    app.register_blueprint(settings_bp)

    return app


# --- Property 16: Dashboard summary counts are correct ---


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    ip_list=ip_list_strategy,
    device_list=device_list_strategy,
)
def test_dashboard_summary_counts_are_correct(ip_list, device_list):
    """**Validates: Requirements 7.6**

    For any set of blocklist entries and managed devices with various statuses,
    the summary counts (total blocked IPs, total devices, online devices,
    offline devices) should equal the actual counts derived from the data.
    """
    db_path = fresh_db()
    try:
        # Insert blocklist entries
        blocklist_service = BlocklistService(db_path=db_path)
        for ip in ip_list:
            blocklist_service.add_ip(ip, "testuser", "test note")

        # Insert devices directly into the database with specific statuses
        device_manager = DeviceManager(db_path=db_path)
        for hostname, device_type, status in device_list:
            if device_type == "pfsense":
                device = device_manager.add_pfsense(
                    hostname, "admin", "pass", "null_route"
                )
            else:
                device = device_manager.add_linux(hostname, 22, "root")
            # Update the status directly in the DB
            with get_db(db_path) as conn:
                conn.execute(
                    "UPDATE managed_devices SET status = ? WHERE id = ?",
                    (status, device["id"]),
                )

        # Compute expected counts from the data
        expected_total_blocked = len(ip_list)
        expected_total_devices = len(device_list)
        expected_online = sum(1 for _, _, s in device_list if s == "online")
        expected_offline = sum(1 for _, _, s in device_list if s == "offline")

        # Create the Flask test app and hit the dashboard route
        from unittest.mock import patch

        app = create_test_app(db_path)
        with app.test_client() as client:
            # Authenticate
            with client.session_transaction() as sess:
                sess["user"] = "admin"

            # Patch Config.DATABASE_PATH so the route uses our temp DB
            with patch("routes.dashboard_routes.Config") as MockConfig:
                MockConfig.DATABASE_PATH = db_path
                resp = client.get("/dashboard")

            assert resp.status_code == 200
            html = resp.data.decode("utf-8")

            # Extract the summary counts from the rendered HTML
            # The template renders counts inside <p class="card-text display-6">
            count_pattern = r'<p class="card-text display-6">(\d+)</p>'
            counts = re.findall(count_pattern, html)

            assert len(counts) == 4, (
                f"Expected 4 summary count cards, found {len(counts)}: {counts}"
            )

            rendered_total_blocked = int(counts[0])
            rendered_total_devices = int(counts[1])
            rendered_online = int(counts[2])
            rendered_offline = int(counts[3])

            assert rendered_total_blocked == expected_total_blocked, (
                f"Total blocked: expected {expected_total_blocked}, got {rendered_total_blocked}"
            )
            assert rendered_total_devices == expected_total_devices, (
                f"Total devices: expected {expected_total_devices}, got {rendered_total_devices}"
            )
            assert rendered_online == expected_online, (
                f"Online count: expected {expected_online}, got {rendered_online}"
            )
            assert rendered_offline == expected_offline, (
                f"Offline count: expected {expected_offline}, got {rendered_offline}"
            )
    finally:
        os.unlink(db_path)
