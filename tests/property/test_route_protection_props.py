# Feature: soc-ip-blocker, Property 1: Route protection redirects unauthenticated users
"""Property-based tests for route protection of unauthenticated users."""

import os
import tempfile

from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from app import create_app
from config import Config
from database import init_db


# --- Strategies ---

# All protected routes in the application with their HTTP methods and URL patterns.
# Routes with dynamic segments use a placeholder integer ID.
PROTECTED_ROUTES = [
    ("GET", "/dashboard"),
    ("POST", "/dashboard/refresh"),
    ("POST", "/blocklist/add"),
    ("POST", "/blocklist/remove/{ip}"),
    ("POST", "/devices/add"),
    ("POST", "/devices/edit/{device_id}"),
    ("POST", "/devices/remove/{device_id}"),
    ("POST", "/devices/test/{device_id}"),
    ("GET", "/settings"),
    ("POST", "/settings/update"),
    ("POST", "/settings/floating-rule/{device_id}"),
]

protected_route_strategy = st.sampled_from(PROTECTED_ROUTES)

# Generate placeholder values for dynamic URL segments
placeholder_ip_strategy = st.just("10.0.0.1")
placeholder_id_strategy = st.integers(min_value=1, max_value=9999)


# --- Helpers ---

def _build_url(url_template: str, ip: str, device_id: int) -> str:
    """Replace URL placeholders with concrete values."""
    return url_template.replace("{ip}", ip).replace("{device_id}", str(device_id))


def _make_test_app():
    """Create a Flask test app with a fresh temporary database."""
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(db_path)

    class TestConfig(Config):
        TESTING = True
        DATABASE_PATH = db_path
        SECRET_KEY = "test-secret"

    app = create_app(config_class=TestConfig)
    return app, db_path


# --- Tests ---

@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    route=protected_route_strategy,
    ip=placeholder_ip_strategy,
    device_id=placeholder_id_strategy,
)
def test_unauthenticated_requests_are_redirected_to_login(
    route: tuple, ip: str, device_id: int
):
    """**Validates: Requirements 1.1**

    For any protected route in the application, an HTTP request without an
    active session should result in a redirect (HTTP 302) to the login page.
    """
    method, url_template = route
    url = _build_url(url_template, ip, device_id)

    app, db_path = _make_test_app()
    try:
        with app.test_client() as client:
            if method == "GET":
                response = client.get(url)
            else:
                response = client.post(url)

            assert response.status_code == 302, (
                f"Expected 302 redirect for unauthenticated {method} {url}, "
                f"got {response.status_code}"
            )

            location = response.headers.get("Location", "")
            assert "/login" in location, (
                f"Expected redirect to /login for unauthenticated {method} {url}, "
                f"got Location: {location}"
            )
    finally:
        os.unlink(db_path)
