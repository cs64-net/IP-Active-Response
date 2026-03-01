"""IP Active Response - Flask application factory."""

import atexit
import logging
import os
import subprocess
import sys
import traceback

import click
from flask import Flask, flash, render_template

from apscheduler.schedulers.background import BackgroundScheduler
from config import Config
from database import get_db, init_db

logger = logging.getLogger(__name__)

# Module-level references so atexit can stop them
_status_monitor = None
_queue_processor = None
_reconciliation_scheduler = None
_alert_forwarder = None


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
    global _status_monitor, _queue_processor, _reconciliation_scheduler, _alert_forwarder

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
    from routes.operation_routes import operations_bp
    from routes.feed_routes import feed_bp
    from routes.api_routes import api_bp
    from routes.honeypot_routes import honeypot_bp
    from routes.dns_block_routes import dns_block_bp
    from routes.geo_routes import geo_bp
    from routes.about_routes import about_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(blocklist_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(operations_bp)
    app.register_blueprint(feed_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(honeypot_bp)
    app.register_blueprint(dns_block_bp)
    app.register_blueprint(geo_bp)
    app.register_blueprint(about_bp)

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

    # Start QueueProcessor for background operation queue processing
    from services.queue_processor import QueueProcessor

    poll_interval = 5
    _queue_processor = QueueProcessor(db_path=db_path, poll_interval=poll_interval)
    _queue_processor.start()

    # Start ReconciliationEngine on a scheduled interval
    from services.reconciliation_engine import ReconciliationEngine
    from services.rules_engine import cleanup_audit_log

    reconciliation_interval = 900
    try:
        with get_db(db_path) as conn:
            row = conn.execute(
                "SELECT reconciliation_interval FROM app_settings WHERE id = 1"
            ).fetchone()
            if row and row["reconciliation_interval"]:
                reconciliation_interval = row["reconciliation_interval"]
    except Exception:
        logger.warning("Could not read reconciliation interval from DB, using default")

    reconciliation_engine = ReconciliationEngine(db_path=db_path)
    _reconciliation_scheduler = BackgroundScheduler()
    _reconciliation_scheduler.add_job(
        reconciliation_engine.run_reconciliation,
        "interval",
        seconds=reconciliation_interval,
        id="reconciliation_engine",
    )
    _reconciliation_scheduler.add_job(
        lambda: cleanup_audit_log(db_path),
        "interval",
        hours=24,
        id="audit_log_cleanup",
    )
    _reconciliation_scheduler.start()

    # Initialize FeedScheduler for external blocklist feeds
    try:
        from routes.feed_routes import init_feed_routes
        from services.feed_manager import FeedManager
        from services.feed_scheduler import FeedScheduler

        feed_manager = FeedManager(db_path=db_path)
        feed_scheduler = FeedScheduler(_reconciliation_scheduler, feed_manager)
        init_feed_routes(feed_scheduler)
        feed_scheduler.restore_all()
        logger.info("Feed scheduler initialized and feeds restored")

        # Initialize geo-blocking routes with the shared feed scheduler
        from routes.geo_routes import init_geo_routes
        init_geo_routes(feed_scheduler)
    except Exception:
        logger.exception("Failed to initialize feed scheduler; app will continue without feed scheduling")

    # Initialize DNSBlockScheduler for DNS-based domain blocking
    try:
        from routes.dns_block_routes import init_dns_block_routes
        from services.dns_block_manager import DNSBlockManager
        from services.dns_block_scheduler import DNSBlockScheduler

        dns_block_manager = DNSBlockManager(db_path=db_path)
        dns_block_scheduler = DNSBlockScheduler(_reconciliation_scheduler, dns_block_manager)
        init_dns_block_routes(dns_block_scheduler)
        dns_block_scheduler.restore_all()
        logger.info("DNS block scheduler initialized and entries restored")
    except Exception:
        logger.exception("Failed to initialize DNS block scheduler; app will continue without DNS block scheduling")

    # Initialize HoneypotManager and wire expiry check job
    try:
        from routes.honeypot_routes import init_honeypot_routes
        from services.alert_forwarder import AlertForwarder
        from services.honeypot_manager import HoneypotManager

        _alert_forwarder = AlertForwarder(db_path=db_path)
        honeypot_manager = HoneypotManager(db_path=db_path, alert_forwarder=_alert_forwarder)
        init_honeypot_routes(honeypot_manager, alert_forwarder=_alert_forwarder)

        # Restore honeypot expiry interval from app_settings
        honeypot_expiry_interval = 60
        try:
            with get_db(db_path) as conn:
                row = conn.execute(
                    "SELECT honeypot_timeout FROM app_settings WHERE id = 1"
                ).fetchone()
                if row and row["honeypot_timeout"]:
                    logger.info("Restored honeypot timeout: %s seconds", row["honeypot_timeout"])
        except Exception:
            logger.warning("Could not read honeypot settings from DB, using defaults")

        def honeypot_expiry_check():
            try:
                honeypot_manager.run_expiry_check()
                honeypot_manager.cleanup_old_alerts()
            except Exception:
                logger.exception("Error during honeypot expiry check")

        _reconciliation_scheduler.add_job(
            honeypot_expiry_check,
            "interval",
            seconds=honeypot_expiry_interval,
            id="honeypot_expiry_check",
        )
        logger.info("Honeypot manager initialized and expiry check scheduled (interval=%ss)", honeypot_expiry_interval)
    except Exception:
        logger.exception("Failed to initialize honeypot manager; app will continue without honeypot integration")

    # Register CLI commands
    @app.cli.command("build-offline-bundle")
    @click.option(
        "--output",
        default="offline_bundle/opencanary-offline.tar.gz",
        help="Output path for the bundle archive.",
    )
    def cli_build_offline_bundle(output):
        """Build the OpenCanary offline installation bundle."""
        from scripts.build_offline_bundle import build_offline_bundle

        try:
            result = build_offline_bundle(output_path=output)
            click.echo(f"Bundle built successfully: {result}")
        except FileNotFoundError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            click.echo(
                f"Error: pip download failed with exit code {e.returncode}",
                err=True,
            )
            if e.stderr:
                click.echo(e.stderr, err=True)
            sys.exit(1)
        except OSError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

    atexit.register(_shutdown_all)

    logger.info("IP Active Response app created successfully")
    return app


def _shutdown_all():
    """Stop all background services on application shutdown."""
    global _status_monitor, _queue_processor, _reconciliation_scheduler, _alert_forwarder
    if _status_monitor is not None:
        _status_monitor.stop()
        _status_monitor = None
    if _queue_processor is not None:
        _queue_processor.stop()
        _queue_processor = None
    if _reconciliation_scheduler is not None:
        try:
            _reconciliation_scheduler.shutdown(wait=False)
        except Exception:
            pass
        _reconciliation_scheduler = None
    if _alert_forwarder is not None:
        try:
            _alert_forwarder.shutdown()
        except Exception:
            pass
        _alert_forwarder = None


if __name__ == "__main__":
    app = create_app()
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
