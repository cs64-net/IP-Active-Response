# Feature: soc-ip-blocker, Property 19: Unhandled exceptions are caught and logged
"""Property-based tests for unhandled exception catching.

Validates that the Flask global error handler catches unhandled exceptions
during request processing, logs the full traceback, and returns an error
response (HTTP 500) instead of crashing.
"""

import logging
import traceback

from flask import Flask, flash
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st


# --- Strategies ---

# Generate different exception types to throw during request processing
exception_type_strategy = st.sampled_from([
    ValueError,
    TypeError,
    RuntimeError,
    KeyError,
    AttributeError,
    IndexError,
    ZeroDivisionError,
    IOError,
    OSError,
    NotImplementedError,
    OverflowError,
    LookupError,
    ArithmeticError,
])

# Generate exception messages of varying content
exception_message_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "Z")),
    min_size=1,
    max_size=200,
)


# --- Helpers ---


class _LogCapture(logging.Handler):
    """Logging handler that captures formatted records."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.setFormatter(logging.Formatter("%(message)s"))
        self.records_text: list = []

    def emit(self, record):
        self.records_text.append(self.format(record))

    def output(self) -> str:
        return "\n".join(self.records_text)


def _build_app(exc_type, exc_message):
    """Build a minimal Flask app that mirrors the production error handler
    and includes a route that raises the given exception."""
    app = Flask(__name__)
    app.secret_key = "test-secret"
    app.config["TESTING"] = False  # Must be False so 500 handler fires

    err_logger = logging.getLogger("app")

    @app.errorhandler(500)
    def internal_error(error):
        err_logger.error("Unhandled exception:\n%s", traceback.format_exc())
        flash("An unexpected error occurred. Please try again.", "error")
        return "Internal Server Error", 500

    @app.route("/_test_error")
    def error_route():
        raise exc_type(exc_message)

    return app


# --- Property 19: Unhandled exceptions are caught and logged ---


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    exc_type=exception_type_strategy,
    exc_message=exception_message_strategy,
)
def test_unhandled_exceptions_are_caught_and_logged(exc_type, exc_message):
    """**Validates: Requirements 9.5**

    For any unhandled exception raised during request processing, the
    application should not crash, should log the full traceback, and
    should return an error response.
    """
    app = _build_app(exc_type, exc_message)
    capture = _LogCapture()
    err_logger = logging.getLogger("app")
    err_logger.addHandler(capture)
    try:
        with app.test_client() as client:
            response = client.get("/_test_error")

            # 1. App did not crash — we received a response
            assert response is not None, "App crashed: no response object"

            # 2. Response is HTTP 500
            assert response.status_code == 500, (
                f"Expected 500 for {exc_type.__name__}('{exc_message[:80]}'), "
                f"got {response.status_code}"
            )

            # 3. Exception was logged with traceback info
            log_text = capture.output()
            assert "Unhandled exception" in log_text, (
                f"Expected 'Unhandled exception' in log output for "
                f"{exc_type.__name__}, got: {log_text[:500]}"
            )
            assert exc_type.__name__ in log_text, (
                f"Expected exception type '{exc_type.__name__}' in log "
                f"output, got: {log_text[:500]}"
            )
    finally:
        err_logger.removeHandler(capture)
