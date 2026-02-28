"""DNSBlockScheduler - Manages APScheduler jobs for periodic DNS refresh cycles."""

import logging

from apscheduler.jobstores.base import JobLookupError
from apscheduler.schedulers.background import BackgroundScheduler

from services.dns_block_manager import DNSBlockManager

logger = logging.getLogger(__name__)


class DNSBlockScheduler:
    """Manages APScheduler interval jobs for periodic DNS refresh cycles.

    Uses the shared BackgroundScheduler instance from app.py and delegates
    refresh execution to DNSBlockManager.refresh_entry.
    """

    JOB_ID_PREFIX = "dns_refresh_"

    def __init__(self, scheduler: BackgroundScheduler, dns_block_manager: DNSBlockManager):
        """Initialize with shared APScheduler instance and DNSBlockManager.

        Args:
            scheduler: The shared BackgroundScheduler from app.py.
            dns_block_manager: DNSBlockManager instance used to execute refreshes.
        """
        self.scheduler = scheduler
        self.dns_block_manager = dns_block_manager

    def _job_id(self, entry_id: int) -> str:
        """Return the APScheduler job ID for a given DNS block entry."""
        return f"{self.JOB_ID_PREFIX}{entry_id}"

    def schedule_entry(self, entry_id: int, interval_seconds: int) -> None:
        """Add or replace a scheduled refresh job for a DNS block entry.

        If a job already exists for this entry, it is removed first so the
        new interval takes effect immediately.

        Args:
            entry_id: Database ID of the DNS block entry.
            interval_seconds: Refresh interval in seconds.
        """
        job_id = self._job_id(entry_id)

        # Remove existing job if present (replace semantics)
        try:
            self.scheduler.remove_job(job_id)
        except JobLookupError:
            pass

        self.scheduler.add_job(
            self.dns_block_manager.refresh_entry,
            trigger="interval",
            seconds=interval_seconds,
            id=job_id,
            args=[entry_id],
            kwargs={"trigger": "scheduled"},
            replace_existing=True,
        )
        logger.info(
            "Scheduled DNS block entry %d with interval %ds (job_id=%s)",
            entry_id, interval_seconds, job_id,
        )

    def cancel_entry(self, entry_id: int) -> None:
        """Remove the scheduled job for a DNS block entry.

        Args:
            entry_id: Database ID of the DNS block entry to cancel.
        """
        job_id = self._job_id(entry_id)
        try:
            self.scheduler.remove_job(job_id)
            logger.info("Cancelled scheduled job for DNS block entry %d (job_id=%s)", entry_id, job_id)
        except JobLookupError:
            logger.warning(
                "No scheduled job found for DNS block entry %d (job_id=%s), nothing to cancel",
                entry_id, job_id,
            )

    def reschedule_entry(self, entry_id: int, interval_seconds: int) -> None:
        """Update the interval for an existing DNS block entry job.

        If the job does not exist, a new one is created via schedule_entry.

        Args:
            entry_id: Database ID of the DNS block entry.
            interval_seconds: New refresh interval in seconds.
        """
        job_id = self._job_id(entry_id)
        try:
            self.scheduler.reschedule_job(
                job_id,
                trigger="interval",
                seconds=interval_seconds,
            )
            logger.info(
                "Rescheduled DNS block entry %d to interval %ds (job_id=%s)",
                entry_id, interval_seconds, job_id,
            )
        except JobLookupError:
            logger.warning(
                "No existing job for DNS block entry %d, creating new schedule", entry_id,
            )
            self.schedule_entry(entry_id, interval_seconds)

    def restore_all(self, stagger_seconds: int = 2) -> None:
        """On app startup, schedule jobs for all enabled DNS block entries.

        Queries all entries via DNSBlockManager and schedules a refresh job
        for each enabled entry. Jobs are staggered with incremental initial
        delays to avoid a thundering herd of concurrent dig calls.

        Args:
            stagger_seconds: Delay in seconds between each job's initial fire time.
        """
        entries = self.dns_block_manager.get_all_entries()
        scheduled_count = 0
        for idx, entry in enumerate(entries):
            if entry.get("enabled") or entry.get("enabled") == 1:
                try:
                    job_id = self._job_id(entry["id"])

                    # Remove existing job if present
                    try:
                        self.scheduler.remove_job(job_id)
                    except JobLookupError:
                        pass

                    # Stagger initial delay: first entry runs after stagger_seconds,
                    # second after 2 * stagger_seconds, etc.
                    initial_delay = (idx + 1) * stagger_seconds

                    self.scheduler.add_job(
                        self.dns_block_manager.refresh_entry,
                        trigger="interval",
                        seconds=entry["refresh_interval"],
                        id=job_id,
                        args=[entry["id"]],
                        kwargs={"trigger": "scheduled"},
                        replace_existing=True,
                        next_run_time=self._staggered_run_time(initial_delay),
                    )
                    scheduled_count += 1
                except Exception:
                    logger.exception(
                        "Failed to schedule DNS block entry '%s' (id=%d) during restore",
                        entry.get("domain"), entry["id"],
                    )
        logger.info(
            "Restored %d scheduled DNS block jobs out of %d total entries",
            scheduled_count, len(entries),
        )

    @staticmethod
    def _staggered_run_time(delay_seconds: int):
        """Calculate a staggered next_run_time from now.

        Args:
            delay_seconds: Number of seconds from now for the first run.

        Returns:
            A datetime representing the staggered initial run time.
        """
        from datetime import datetime, timedelta, timezone
        return datetime.now(timezone.utc) + timedelta(seconds=delay_seconds)
