"""FeedScheduler - Manages APScheduler jobs for periodic feed refreshes."""

import logging

from apscheduler.jobstores.base import JobLookupError
from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger(__name__)


class FeedScheduler:
    """Manages APScheduler interval jobs for periodic feed refreshes.

    Uses the shared BackgroundScheduler instance from app.py and delegates
    refresh execution to FeedManager.refresh_feed.
    """

    JOB_ID_PREFIX = "feed_refresh_"

    def __init__(self, scheduler: BackgroundScheduler, feed_manager):
        """Initialize with shared APScheduler instance and FeedManager.

        Args:
            scheduler: The shared BackgroundScheduler from app.py.
            feed_manager: FeedManager instance used to execute refreshes.
        """
        self.scheduler = scheduler
        self.feed_manager = feed_manager

    def _job_id(self, feed_id: int) -> str:
        """Return the APScheduler job ID for a given feed."""
        return f"{self.JOB_ID_PREFIX}{feed_id}"

    def schedule_feed(self, feed_id: int, interval_seconds: int) -> None:
        """Add or replace a scheduled job for a feed.

        If a job already exists for this feed, it is removed first so the
        new interval takes effect immediately.

        Args:
            feed_id: Database ID of the feed.
            interval_seconds: Refresh interval in seconds.
        """
        job_id = self._job_id(feed_id)

        # Remove existing job if present (replace semantics)
        try:
            self.scheduler.remove_job(job_id)
        except JobLookupError:
            pass

        self.scheduler.add_job(
            self.feed_manager.refresh_feed,
            trigger="interval",
            seconds=interval_seconds,
            id=job_id,
            args=[feed_id],
            kwargs={"trigger": "scheduled"},
            replace_existing=True,
        )
        logger.info(
            "Scheduled feed %d with interval %ds (job_id=%s)",
            feed_id, interval_seconds, job_id,
        )

    def cancel_feed(self, feed_id: int) -> None:
        """Remove the scheduled job for a feed.

        Args:
            feed_id: Database ID of the feed to cancel.
        """
        job_id = self._job_id(feed_id)
        try:
            self.scheduler.remove_job(job_id)
            logger.info("Cancelled scheduled job for feed %d (job_id=%s)", feed_id, job_id)
        except JobLookupError:
            logger.warning(
                "No scheduled job found for feed %d (job_id=%s), nothing to cancel",
                feed_id, job_id,
            )

    def reschedule_feed(self, feed_id: int, interval_seconds: int) -> None:
        """Update the interval for an existing feed job.

        If the job does not exist, a new one is created via schedule_feed.

        Args:
            feed_id: Database ID of the feed.
            interval_seconds: New refresh interval in seconds.
        """
        job_id = self._job_id(feed_id)
        try:
            self.scheduler.reschedule_job(
                job_id,
                trigger="interval",
                seconds=interval_seconds,
            )
            logger.info(
                "Rescheduled feed %d to interval %ds (job_id=%s)",
                feed_id, interval_seconds, job_id,
            )
        except JobLookupError:
            logger.warning(
                "No existing job for feed %d, creating new schedule", feed_id,
            )
            self.schedule_feed(feed_id, interval_seconds)

    def restore_all(self) -> None:
        """On app startup, schedule jobs for all enabled feeds from DB.

        Queries all feeds via FeedManager and schedules a refresh job for
        each enabled feed. Disabled feeds are skipped.
        """
        feeds = self.feed_manager.get_all_feeds()
        scheduled_count = 0
        for feed in feeds:
            if feed.get("enabled") or feed.get("enabled") == 1:
                try:
                    self.schedule_feed(feed["id"], feed["refresh_interval"])
                    scheduled_count += 1
                except Exception:
                    logger.exception(
                        "Failed to schedule feed '%s' (id=%d) during restore",
                        feed.get("name"), feed["id"],
                    )
        logger.info(
            "Restored %d scheduled feed jobs out of %d total feeds",
            scheduled_count, len(feeds),
        )
