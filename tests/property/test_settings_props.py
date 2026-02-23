# Feature: soc-ip-blocker, Property 20: Default block method applies to new pfSense devices
"""Property-based tests for settings — default block method inheritance."""

import os
import tempfile

from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from database import get_db, init_db
from services.device_manager import DeviceManager


# --- Strategies ---

block_method_strategy = st.sampled_from(["null_route", "floating_rule"])

hostname_strategy = st.one_of(
    st.tuples(
        st.integers(min_value=1, max_value=254),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=1, max_value=254),
    ).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}"),
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


def fresh_db():
    """Create a fresh temporary database and return its path."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    return path


# --- Property 20: Default block method applies to new pfSense devices ---


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    default_method=block_method_strategy,
    hostname=hostname_strategy,
    username=username_strategy,
    password=password_strategy,
)
def test_default_block_method_inherited_by_new_pfsense(
    default_method: str, hostname: str, username: str, password: str
):
    """**Validates: Requirements 10.3**

    For any default block method setting, a subsequently added pfSense firewall
    that does not specify a block method should inherit the configured default.

    This test:
    1. Sets the default_block_method in app_settings
    2. Reads it back (as the route/UI would)
    3. Adds a pfSense device using that default
    4. Verifies the device's block_method matches the configured default
    """
    db_path = fresh_db()
    try:
        # Step 1: Update the default block method in app_settings
        with get_db(db_path) as conn:
            conn.execute(
                "UPDATE app_settings SET default_block_method = ? WHERE id = 1",
                (default_method,),
            )

        # Step 2: Read the default back from app_settings (simulating what the
        # route/UI does when a user adds a device without choosing a method)
        with get_db(db_path) as conn:
            row = conn.execute(
                "SELECT default_block_method FROM app_settings WHERE id = 1"
            ).fetchone()
            inherited_method = row["default_block_method"]

        # The read-back value must match what was set
        assert inherited_method == default_method, (
            f"app_settings default should be '{default_method}' but got '{inherited_method}'"
        )

        # Step 3: Add a pfSense device using the inherited default
        # (this is what happens when the form doesn't override the block method)
        dm = DeviceManager(db_path=db_path)
        device = dm.add_pfsense(hostname, username, password, inherited_method)

        # Step 4: Verify the device inherited the configured default
        assert device["block_method"] == default_method, (
            f"Device block_method should be '{default_method}' but got '{device['block_method']}'"
        )

        # Also verify persistence: re-read from DB
        all_devices = dm.get_all_devices()
        assert len(all_devices) == 1
        persisted = all_devices[0]
        assert persisted["block_method"] == default_method, (
            f"Persisted block_method should be '{default_method}' but got '{persisted['block_method']}'"
        )
    finally:
        os.unlink(db_path)


# Feature: soc-ip-blocker, Property 21: Settings validation rejects invalid inputs

from unittest.mock import patch

from flask import Flask

from routes.settings_routes import settings_bp
from routes.auth_routes import auth_bp


# --- Strategies for invalid settings ---

# Invalid monitor intervals: negative, zero, non-numeric strings, empty
invalid_monitor_interval_strategy = st.one_of(
    # Negative integers
    st.integers(min_value=-10000, max_value=-1).map(str),
    # Zero
    st.just("0"),
    # Non-numeric strings
    st.text(
        alphabet=st.characters(whitelist_categories=("L",)),
        min_size=1,
        max_size=20,
    ),
    # Empty string
    st.just(""),
    # Floats (not valid integers)
    st.floats(min_value=-1000, max_value=1000, allow_nan=False, allow_infinity=False)
    .filter(lambda f: f != int(f) if f == f else True)
    .map(lambda f: f"{f:.2f}"),
)

# Invalid block methods: anything not "null_route" or "floating_rule"
invalid_block_method_strategy = st.text(min_size=0, max_size=50).filter(
    lambda s: s.strip() not in ("null_route", "floating_rule")
)

# Valid monitor interval for use when testing invalid block method only
valid_monitor_interval_strategy = st.integers(min_value=1, max_value=86400).map(str)

# Valid block method for use when testing invalid interval only
valid_block_method_strategy = st.sampled_from(["null_route", "floating_rule"])


def create_settings_test_app(db_path):
    """Create a minimal Flask app for settings route testing."""
    app = Flask(__name__, template_folder=os.path.join(
        os.path.dirname(__file__), "..", "..", "templates"
    ))
    app.secret_key = "test-secret"
    app.config["TESTING"] = True

    app.register_blueprint(auth_bp)
    app.register_blueprint(settings_bp)

    return app


# --- Property 21: Settings validation rejects invalid inputs ---


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    invalid_interval=invalid_monitor_interval_strategy,
    valid_method=valid_block_method_strategy,
)
def test_settings_rejects_invalid_monitor_interval(invalid_interval, valid_method):
    """**Validates: Requirements 10.5**

    For any invalid monitor interval (negative, zero, non-numeric, empty),
    the settings save operation should reject the input and return a
    validation error via redirect with flash message.
    """
    db_path = fresh_db()
    try:
        app = create_settings_test_app(db_path)
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["user"] = "admin"

            with patch("routes.settings_routes.Config") as MockConfig:
                MockConfig.DATABASE_PATH = db_path
                resp = client.post(
                    "/settings/update",
                    data={
                        "monitor_interval": invalid_interval,
                        "default_block_method": valid_method,
                    },
                    follow_redirects=False,
                )

            # Should redirect (302) back to settings page
            assert resp.status_code == 302, (
                f"Expected redirect 302 for invalid interval '{invalid_interval}', "
                f"got {resp.status_code}"
            )

            # Verify the settings were NOT changed in the database
            with get_db(db_path) as conn:
                row = conn.execute(
                    "SELECT monitor_interval, default_block_method FROM app_settings WHERE id = 1"
                ).fetchone()
                # Default seeded values should remain
                assert row["monitor_interval"] == 300, (
                    f"monitor_interval should remain 300 but got {row['monitor_interval']} "
                    f"for invalid input '{invalid_interval}'"
                )
    finally:
        os.unlink(db_path)


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    valid_interval=valid_monitor_interval_strategy,
    invalid_method=invalid_block_method_strategy,
)
def test_settings_rejects_invalid_block_method(valid_interval, invalid_method):
    """**Validates: Requirements 10.5**

    For any invalid block method (not 'null_route' or 'floating_rule'),
    the settings save operation should reject the input and return a
    validation error via redirect with flash message.
    """
    db_path = fresh_db()
    try:
        app = create_settings_test_app(db_path)
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["user"] = "admin"

            with patch("routes.settings_routes.Config") as MockConfig:
                MockConfig.DATABASE_PATH = db_path
                resp = client.post(
                    "/settings/update",
                    data={
                        "monitor_interval": valid_interval,
                        "default_block_method": invalid_method,
                    },
                    follow_redirects=False,
                )

            # Should redirect (302) back to settings page
            assert resp.status_code == 302, (
                f"Expected redirect 302 for invalid method '{invalid_method}', "
                f"got {resp.status_code}"
            )

            # Verify the settings were NOT changed in the database
            with get_db(db_path) as conn:
                row = conn.execute(
                    "SELECT monitor_interval, default_block_method FROM app_settings WHERE id = 1"
                ).fetchone()
                # Default seeded values should remain
                assert row["default_block_method"] == "null_route", (
                    f"default_block_method should remain 'null_route' but got "
                    f"'{row['default_block_method']}' for invalid input '{invalid_method}'"
                )
    finally:
        os.unlink(db_path)
