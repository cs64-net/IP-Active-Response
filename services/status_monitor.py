"""Background status monitor for periodic device health checks.

Uses APScheduler to run health checks against all managed devices
at a configurable interval, updating their status in the database.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Optional

from apscheduler.schedulers.background import BackgroundScheduler

from database import get_db

logger = logging.getLogger(__name__)


class StatusMonitor:
    """Periodically checks connectivity of all managed devices."""

    def __init__(self, db_path=None, interval_seconds: int = 300):
        """Initialize with database path and check interval.

        Args:
            db_path: Path to the SQLite database file.
            interval_seconds: Seconds between health check runs.
        """
        self.db_path = db_path
        self.interval_seconds = interval_seconds
        self.scheduler: Optional[BackgroundScheduler] = None

    def start(self) -> None:
        """Start the background scheduler for periodic checks."""
        self.scheduler = BackgroundScheduler()
        self.scheduler.add_job(
            self.check_all_devices,
            "interval",
            seconds=self.interval_seconds,
            id="device_health_check",
        )
        self.scheduler.start()
        logger.info("StatusMonitor started with %ds interval", self.interval_seconds)

    def stop(self) -> None:
        """Stop the background scheduler gracefully."""
        if self.scheduler is not None:
            self.scheduler.shutdown(wait=False)
            self.scheduler = None
            logger.info("StatusMonitor stopped")

    def check_all_devices(self) -> Dict[int, str]:
        """Check all devices and update their status in the database.

        Returns:
            Dict mapping device_id to status string ("online" or "offline").
        """
        results = {}
        with get_db(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM managed_devices ORDER BY id"
            ).fetchall()
            devices = [dict(r) for r in rows]

        for device in devices:
            status = self.check_device(device)
            results[device["id"]] = status
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            with get_db(self.db_path) as conn:
                conn.execute(
                    "UPDATE managed_devices SET status = ?, last_checked = ? WHERE id = ?",
                    (status, now, device["id"]),
                )

        logger.info("Health check complete: %s", results)
        return results

    CLOUD_DEVICE_TYPES = {"aws_waf", "azure_nsg", "gcp_firewall", "oci_nsg"}

    def check_device(self, device: Dict) -> str:
        """Check a single device's connectivity.

        For on-prem devices, uses HTTP(S) or socket checks.
        For cloud devices, instantiates the cloud client and calls check_health().

        Args:
            device: Device dict with keys from managed_devices table.

        Returns:
            "online" if reachable, "offline" otherwise.
        """
        import requests
        hostname = device.get("hostname", "")
        device_type = device.get("device_type", "")
        try:
            if device_type in self.CLOUD_DEVICE_TYPES:
                from services.push_orchestrator import CLIENT_REGISTRY
                factory = CLIENT_REGISTRY.get(device_type)
                if factory is None:
                    logger.debug("No factory for cloud device type %s", device_type)
                    return "offline"
                client = factory(device)
                return "online" if client.check_health() else "offline"
            elif device_type == "pfsense":
                url = hostname if hostname.startswith(("http://", "https://")) else f"https://{hostname}"
                resp = requests.get(f"{url}/index.php", timeout=10, verify=False)
                return "online" if resp.status_code == 200 else "offline"
            elif device_type in ("linux", "cisco_ios", "cisco_asa", "fortinet", "palo_alto"):
                import socket
                port = device.get("ssh_port", 22)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                result = sock.connect_ex((hostname, port))
                sock.close()
                return "online" if result == 0 else "offline"
            elif device_type == "unifi":
                api_port = device.get("api_port", 443)
                url = f"https://{hostname}:{api_port}/"
                resp = requests.get(url, timeout=10, verify=False)
                return "online" if resp.status_code == 200 else "offline"
            else:
                return "offline"
        except Exception as e:
            logger.debug("Health check failed for %s: %s", hostname, e)
            return "offline"
