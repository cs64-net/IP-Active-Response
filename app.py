"""SOC IP Blocker - Flask application factory."""

import atexit
import logging
import traceback

from flask import Flask, flash, render_template

from config import Config
from database import get_db, init_db

logger = logging.getLogger(__name__)

# Module-level reference so atexit can stop it
_status_monitor = None


def _configure_logging():
    """Configure logging to file and console."""
    import os
    fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Write log file next to the database for Docker volume persistence
    db_path = os.environ.get("DATABASE_PATH", "")
    if db_path:
        log_dir = os.path.dirname(db_path)
        log_path = os.path.join(log_dir, "soc_ip_blocker.log") if log_dir else "soc_ip_blocker.log"
    else:
        log_path = "soc_ip_blocker.log"

    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[
            logging.FileHandler(log_path),
            logging.StreamHandler(),
        ],
    )


def create_app(config_class=Config):
    """Application factory: create and configure the Flask app."""
    global _status_monitor

    _configure_logging()

    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize database
    db_path = app.config.get("DATABASE_PATH", Config.DATABASE_PATH)
    init_db(db_path)

    # Register blueprints
    from routes.auth_routes import auth_bp
    from routes.blocklist_routes import blocklist_bp
    from routes.dashboard_routes import dashboard_bp
    from routes.device_routes import devices_bp
    from routes.settings_routes import settings_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(blocklist_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(settings_bp)

    # Global error handler for unhandled exceptions
    @app.errorhandler(500)
    def internal_error(error):
        logger.error("Unhandled exception:\n%s", traceback.format_exc())
        flash("An unexpected error occurred. Please try again.", "error")
        return render_template("base.html"), 500

    # Start StatusMonitor background scheduler
    from services.status_monitor import StatusMonitor

    monitor_interval = Config.MONITOR_INTERVAL
    try:
        with get_db(db_path) as conn:
            row = conn.execute(
                "SELECT monitor_interval FROM app_settings WHERE id = 1"
            ).fetchone()
            if row:
                monitor_interval = row["monitor_interval"]
    except Exception:
        logger.warning("Could not read monitor interval from DB, using default")

    _status_monitor = StatusMonitor(
        db_path=db_path, interval_seconds=monitor_interval
    )
    _status_monitor.start()

    atexit.register(_shutdown_monitor)

    logger.info("SOC IP Blocker app created successfully")
    return app


def _shutdown_monitor():
    """Stop the StatusMonitor on application shutdown."""
    global _status_monitor
    if _status_monitor is not None:
        _status_monitor.stop()
        _status_monitor = None


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
