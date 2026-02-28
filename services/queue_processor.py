"""Background queue processor that drives the PushOrchestrator on a schedule.

Uses APScheduler to poll the operation queue at a configurable interval
and dispatch pending operations to devices via PushOrchestrator.
"""

import logging
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler

from services.push_orchestrator import PushOrchestrator

logger = logging.getLogger(__name__)


class QueueProcessor:
    """Periodically polls the operation queue and dispatches pending operations."""

    def __init__(self, db_path=None, poll_interval: int = 5):
        """Initialize with database path and poll interval.

        Args:
            db_path: Path to the SQLite database file.
            poll_interval: Seconds between queue polling cycles.
        """
        self.db_path = db_path
        self.poll_interval = poll_interval
        self.orchestrator = PushOrchestrator(db_path)
        self.scheduler: Optional[BackgroundScheduler] = None
        self.running = False

    def start(self) -> None:
        """Start polling the operation queue."""
        self.scheduler = BackgroundScheduler()
        self.scheduler.add_job(
            self.orchestrator.process_pending_operations,
            "interval",
            seconds=self.poll_interval,
            id="queue_processor",
        )
        self.scheduler.start()
        self.running = True
        logger.info("QueueProcessor started with %ds poll interval", self.poll_interval)

    def stop(self) -> None:
        """Gracefully stop processing."""
        if self.scheduler is not None:
            self.scheduler.shutdown(wait=False)
            self.scheduler = None
        self.running = False
        logger.info("QueueProcessor stopped")
