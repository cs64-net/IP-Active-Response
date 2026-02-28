"""AlertForwarder service for asynchronous SIEM forwarding.

Dispatches honeypot alerts to configured Elasticsearch and/or Syslog
destinations via a background thread queue. All forwarding is fire-and-forget:
errors are logged and discarded, never retried.
"""

import logging
import queue
import socket
import ssl
import threading
from datetime import datetime, timezone

import requests

from database import get_db

logger = logging.getLogger(__name__)

# RFC 5424 syslog facility codes
FACILITY_MAP = {
    "kern": 0,
    "user": 1,
    "mail": 2,
    "daemon": 3,
    "auth": 4,
    "syslog": 5,
    "lpr": 6,
    "news": 7,
    "uucp": 8,
    "cron": 9,
    "authpriv": 10,
    "ftp": 11,
    "local0": 16,
    "local1": 17,
    "local2": 18,
    "local3": 19,
    "local4": 20,
    "local5": 21,
    "local6": 22,
    "local7": 23,
}


class ElasticsearchClient:
    """HTTP client for sending alert documents to Elasticsearch."""

    def send(self, alert_doc: dict, settings: dict) -> None:
        """POST alert document to Elasticsearch index.

        Args:
            alert_doc: The alert document to index.
            settings: Dict with elastic_host, elastic_index, elastic_api_key,
                      elastic_tls_verify keys.
        """
        host = settings.get("elastic_host", "").rstrip("/")
        index = settings.get("elastic_index", "honeypot-alerts")
        api_key = settings.get("elastic_api_key")
        tls_verify = bool(settings.get("elastic_tls_verify", 1))

        url = f"{host}/{index}/_doc"

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"

        try:
            resp = requests.post(url, json=alert_doc, headers=headers, verify=tls_verify, timeout=30)
            if not resp.ok:
                logger.error(
                    "Elasticsearch returned HTTP %d: %s",
                    resp.status_code,
                    resp.text,
                )
        except requests.exceptions.RequestException as exc:
            logger.error("Elasticsearch connection error: %s", exc)

    def ping(self, settings: dict) -> dict:
        """GET {host}/ to verify cluster is reachable.

        Args:
            settings: Dict with elastic_host, elastic_tls_verify keys.

        Returns:
            {"success": bool, "message": str}
        """
        host = settings.get("elastic_host", "").rstrip("/")
        tls_verify = bool(settings.get("elastic_tls_verify", 1))

        headers = {}
        api_key = settings.get("elastic_api_key")
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"

        try:
            resp = requests.get(f"{host}/", headers=headers, verify=tls_verify, timeout=10)
            if resp.ok:
                return {"success": True, "message": "Connected to Elasticsearch cluster"}
            return {"success": False, "message": f"HTTP {resp.status_code}: {resp.text}"}
        except requests.exceptions.RequestException as exc:
            return {"success": False, "message": str(exc)}


class SyslogClient:
    """Client for sending RFC 5424 syslog messages."""

    def send(self, message: str, settings: dict) -> None:
        """Send RFC 5424 syslog message to configured server.

        Args:
            message: Formatted syslog message string.
            settings: Dict with syslog_host, syslog_port, syslog_protocol keys.
        """
        host = settings.get("syslog_host", "")
        port = int(settings.get("syslog_port", 514))
        protocol = settings.get("syslog_protocol", "udp").lower()
        data = message.encode("utf-8")

        try:
            if protocol == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.sendto(data, (host, port))
                finally:
                    sock.close()

            elif protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    sock.settimeout(10)
                    sock.connect((host, port))
                    sock.send(data + b"\n")
                finally:
                    sock.close()

            elif protocol == "tcp+tls":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                context = ssl.create_default_context()
                wrapped = context.wrap_socket(sock, server_hostname=host)
                try:
                    wrapped.settimeout(10)
                    wrapped.connect((host, port))
                    wrapped.send(data + b"\n")
                finally:
                    wrapped.close()

            else:
                logger.error("Unknown syslog protocol: %s", protocol)

        except (socket.error, ssl.SSLError, OSError) as exc:
            logger.error("Syslog send error (%s): %s", protocol, exc)

    def test_connection(self, settings: dict) -> dict:
        """Attempt to open a connection to the syslog server.

        Args:
            settings: Dict with syslog_host, syslog_port, syslog_protocol keys.

        Returns:
            {"success": bool, "message": str}
        """
        host = settings.get("syslog_host", "")
        port = int(settings.get("syslog_port", 514))
        protocol = settings.get("syslog_protocol", "udp").lower()

        try:
            if protocol == "udp":
                # UDP is connectionless — just verify the host resolves
                socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
                return {"success": True, "message": f"UDP socket ready for {host}:{port}"}

            elif protocol in ("tcp", "tcp+tls"):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                try:
                    if protocol == "tcp+tls":
                        context = ssl.create_default_context()
                        sock = context.wrap_socket(sock, server_hostname=host)
                    sock.connect((host, port))
                    return {"success": True, "message": f"Connected to {host}:{port} via {protocol.upper()}"}
                finally:
                    sock.close()

            else:
                return {"success": False, "message": f"Unknown protocol: {protocol}"}

        except (socket.error, ssl.SSLError, OSError) as exc:
            return {"success": False, "message": str(exc)}


class AlertForwarder:
    """Asynchronous SIEM alert forwarder with background thread queue.

    Enqueues alert data for dispatch to Elasticsearch and/or Syslog
    destinations. A single background worker thread reads settings from
    the database and dispatches to each enabled destination independently.
    All exceptions are caught per-item and logged.
    """

    _SENTINEL = object()  # Shutdown signal

    def __init__(self, db_path: str = None):
        """Initialize with DB path for reading settings. Starts background worker.

        Args:
            db_path: Path to the SQLite database file. Defaults to Config.DATABASE_PATH.
        """
        self.db_path = db_path
        self._queue = queue.Queue()
        self._es_client = ElasticsearchClient()
        self._syslog_client = SyslogClient()
        self._shutdown_event = threading.Event()
        self._worker = threading.Thread(
            target=self._worker_loop,
            name="alert-forwarder-worker",
            daemon=True,
        )
        self._worker.start()
        logger.info("AlertForwarder started with background worker thread")

    def forward_alert(self, alert_data: dict) -> None:
        """Enqueue an alert for async forwarding. Non-blocking, returns immediately.

        Args:
            alert_data: Dict with keys: attacker_ip, service_name, instance_id,
                        instance_name, alert_timestamp, status, raw_payload
        """
        self._queue.put(alert_data)

    def shutdown(self) -> None:
        """Signal the background worker to finish current work and stop."""
        self._shutdown_event.set()
        self._queue.put(self._SENTINEL)
        self._worker.join(timeout=10)
        logger.info("AlertForwarder shut down")

    def _worker_loop(self) -> None:
        """Background worker: dequeue alerts and dispatch to enabled destinations."""
        while not self._shutdown_event.is_set():
            try:
                item = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue

            if item is self._SENTINEL:
                break

            try:
                self._process_item(item)
            except Exception:
                logger.exception("Unhandled error processing alert forwarding item")
            finally:
                self._queue.task_done()

    def _process_item(self, alert_data: dict) -> None:
        """Read settings and dispatch a single alert to enabled destinations."""
        settings = self._read_settings()

        # Elasticsearch forwarding
        if settings.get("elastic_enabled"):
            try:
                alert_doc = self._build_es_document(alert_data)
                self._es_client.send(alert_doc, settings)
                logger.debug("Forwarded alert to Elasticsearch for %s", alert_data.get("attacker_ip"))
            except Exception:
                logger.exception(
                    "Failed to forward alert to Elasticsearch for %s",
                    alert_data.get("attacker_ip"),
                )

        # Syslog forwarding
        if settings.get("syslog_enabled"):
            try:
                message = self._format_syslog_message(alert_data, settings)
                self._syslog_client.send(message, settings)
                logger.debug("Forwarded alert to Syslog for %s", alert_data.get("attacker_ip"))
            except Exception:
                logger.exception(
                    "Failed to forward alert to Syslog for %s",
                    alert_data.get("attacker_ip"),
                )

    def _read_settings(self) -> dict:
        """Read SIEM settings from the database.

        Returns:
            Dict with all SIEM configuration fields and safe defaults.
        """
        defaults = {
            "elastic_enabled": 0,
            "elastic_host": None,
            "elastic_index": "honeypot-alerts",
            "elastic_api_key": None,
            "elastic_tls_verify": 1,
            "syslog_enabled": 0,
            "syslog_host": None,
            "syslog_port": 514,
            "syslog_protocol": "udp",
            "syslog_facility": "local0",
        }
        try:
            with get_db(self.db_path) as conn:
                row = conn.execute(
                    "SELECT elastic_enabled, elastic_host, elastic_index, elastic_api_key,"
                    " elastic_tls_verify, syslog_enabled, syslog_host, syslog_port,"
                    " syslog_protocol, syslog_facility"
                    " FROM app_settings WHERE id = 1"
                ).fetchone()
                if row:
                    return {
                        "elastic_enabled": row["elastic_enabled"] if row["elastic_enabled"] is not None else 0,
                        "elastic_host": row["elastic_host"],
                        "elastic_index": row["elastic_index"] or "honeypot-alerts",
                        "elastic_api_key": row["elastic_api_key"],
                        "elastic_tls_verify": row["elastic_tls_verify"] if row["elastic_tls_verify"] is not None else 1,
                        "syslog_enabled": row["syslog_enabled"] if row["syslog_enabled"] is not None else 0,
                        "syslog_host": row["syslog_host"],
                        "syslog_port": row["syslog_port"] if row["syslog_port"] is not None else 514,
                        "syslog_protocol": row["syslog_protocol"] or "udp",
                        "syslog_facility": row["syslog_facility"] or "local0",
                    }
        except Exception:
            logger.exception("Failed to read SIEM settings from database")
        return defaults

    @staticmethod
    def _build_es_document(alert_data: dict) -> dict:
        """Build an Elasticsearch alert document from alert data.

        Adds @timestamp in ISO 8601 format.

        Args:
            alert_data: Dict with alert fields.

        Returns:
            Dict suitable for indexing in Elasticsearch.
        """
        doc = {
            "attacker_ip": alert_data.get("attacker_ip"),
            "service_name": alert_data.get("service_name"),
            "instance_id": alert_data.get("instance_id"),
            "instance_name": alert_data.get("instance_name"),
            "alert_timestamp": alert_data.get("alert_timestamp"),
            "status": alert_data.get("status"),
            "raw_payload": alert_data.get("raw_payload"),
            "@timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return doc

    @staticmethod
    def _format_syslog_message(alert_data: dict, settings: dict) -> str:
        """Format an RFC 5424 syslog message from alert data.

        Priority = facility_code * 8 + severity (1 = alert level).

        Args:
            alert_data: Dict with alert fields.
            settings: Dict with syslog_facility key.

        Returns:
            Formatted RFC 5424 syslog message string.
        """
        facility_name = settings.get("syslog_facility", "local0")
        facility_code = FACILITY_MAP.get(facility_name, 16)  # default local0
        severity = 1  # alert level
        priority = facility_code * 8 + severity

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        hostname = socket.gethostname()

        attacker_ip = alert_data.get("attacker_ip", "-")
        service_name = alert_data.get("service_name", "-")
        instance_id = alert_data.get("instance_id", "-")
        status = alert_data.get("status", "-")

        structured_data = (
            f'[alert@0 attacker_ip="{attacker_ip}" service_name="{service_name}"'
            f' instance_id="{instance_id}" status="{status}"]'
        )

        msg = (
            f"Honeypot alert: {service_name} from {attacker_ip}"
            f" on instance {instance_id} — {status}"
        )

        # RFC 5424: <priority>version timestamp hostname app-name procid msgid [SD] msg
        return f"<{priority}>1 {timestamp} {hostname} honeypot-soc - - {structured_data} {msg}"

    @staticmethod
    def test_elasticsearch(settings: dict) -> dict:
        """Test Elasticsearch connectivity with given settings.

        Args:
            settings: Dict with Elasticsearch connection fields.

        Returns:
            {"success": bool, "message": str}
        """
        client = ElasticsearchClient()
        return client.ping(settings)

    @staticmethod
    def test_syslog(settings: dict) -> dict:
        """Test Syslog connectivity with given settings.

        Args:
            settings: Dict with Syslog connection fields.

        Returns:
            {"success": bool, "message": str}
        """
        client = SyslogClient()
        return client.test_connection(settings)
