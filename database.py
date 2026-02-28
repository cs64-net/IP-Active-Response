"""SQLite database initialization and connection helpers for SOC IP Blocker."""

import sqlite3
import threading
from contextlib import contextmanager

from werkzeug.security import generate_password_hash

from config import Config

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS block_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    added_by TEXT NOT NULL,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    note TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS managed_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    device_type TEXT NOT NULL CHECK(device_type IN (
        'pfsense', 'linux', 'cisco_ios', 'cisco_asa',
        'fortinet', 'palo_alto', 'unifi',
        'aws_waf', 'azure_nsg', 'gcp_firewall', 'oci_nsg'
    )),
    status TEXT DEFAULT 'unknown',
    last_checked TIMESTAMP,
    web_username TEXT,
    web_password TEXT,
    block_method TEXT CHECK(block_method IN (
        'null_route', 'floating_rule', 'alias_only', 'cloud_api'
    )),
    ssh_port INTEGER DEFAULT 22,
    ssh_username TEXT,
    ssh_password TEXT,
    ssh_key_path TEXT,
    friendly_name TEXT DEFAULT '',
    ssh_key TEXT DEFAULT '',
    sudo_password TEXT DEFAULT '',
    enable_password TEXT DEFAULT '',
    group_name TEXT DEFAULT 'SOC_BLOCKLIST',
    api_port INTEGER DEFAULT 443,
    cloud_credentials TEXT DEFAULT '',
    cloud_region TEXT DEFAULT '',
    cloud_resource_id TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS push_statuses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    block_entry_id INTEGER NOT NULL REFERENCES block_entries(id) ON DELETE CASCADE,
    device_id INTEGER NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK(status IN ('pending', 'in_progress', 'success', 'failed', 'retrying')),
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    pushed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(block_entry_id, device_id)
);

CREATE TABLE IF NOT EXISTS app_settings (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    monitor_interval INTEGER DEFAULT 300,
    default_block_method TEXT DEFAULT 'floating_rule',
    protected_ranges TEXT DEFAULT '',
    concurrency_limit INTEGER DEFAULT 10,
    max_retry_attempts INTEGER DEFAULT 3,
    retry_backoff_base INTEGER DEFAULT 30,
    reconciliation_interval INTEGER DEFAULT 900,
    audit_retention_days INTEGER DEFAULT 90
);

CREATE TABLE IF NOT EXISTS operation_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL,
    device_id INTEGER NOT NULL REFERENCES managed_devices(id),
    action TEXT NOT NULL CHECK(action IN ('add', 'remove')),
    ip_addresses TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending', 'in_progress', 'completed', 'failed', 'cancelled')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    next_retry_at TIMESTAMP,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    source TEXT DEFAULT 'api'
);

CREATE INDEX IF NOT EXISTS idx_opq_status ON operation_queue(status);
CREATE INDEX IF NOT EXISTS idx_opq_operation_id ON operation_queue(operation_id);
CREATE INDEX IF NOT EXISTS idx_opq_device_id ON operation_queue(device_id);
CREATE INDEX IF NOT EXISTS idx_opq_next_retry ON operation_queue(next_retry_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    user TEXT,
    action TEXT NOT NULL,
    target_ips TEXT,
    device_id INTEGER,
    operation_id TEXT,
    details TEXT,
    FOREIGN KEY (device_id) REFERENCES managed_devices(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_operation_id ON audit_log(operation_id);

CREATE TABLE IF NOT EXISTS feeds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    url TEXT UNIQUE NOT NULL,
    refresh_interval INTEGER NOT NULL DEFAULT 3600,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_fetch_time TIMESTAMP,
    last_fetch_status TEXT DEFAULT 'pending',
    last_fetch_ip_count INTEGER DEFAULT 0,
    last_fetch_duration REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS feed_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_id INTEGER NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
    ip_address TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(feed_id, ip_address)
);

CREATE INDEX IF NOT EXISTS idx_feed_entries_feed_id ON feed_entries(feed_id);
CREATE INDEX IF NOT EXISTS idx_feed_entries_ip ON feed_entries(ip_address);

CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS honeypot_instances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    ip_address TEXT UNIQUE NOT NULL,
    services TEXT NOT NULL DEFAULT '[]',
    token_hash TEXT NOT NULL,
    token_prefix TEXT NOT NULL,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_alert_at TIMESTAMP,
    alert_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS honeypot_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attacker_ip TEXT NOT NULL,
    service_name TEXT NOT NULL,
    instance_id INTEGER NOT NULL REFERENCES honeypot_instances(id) ON DELETE CASCADE,
    alert_timestamp TIMESTAMP NOT NULL,
    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'processed'
        CHECK(status IN ('processed', 'blocked', 'skipped_protected', 'skipped_invalid', 'updated')),
    raw_payload TEXT
);

CREATE INDEX IF NOT EXISTS idx_honeypot_alerts_ip ON honeypot_alerts(attacker_ip);
CREATE INDEX IF NOT EXISTS idx_honeypot_alerts_instance ON honeypot_alerts(instance_id);
CREATE INDEX IF NOT EXISTS idx_honeypot_alerts_timestamp ON honeypot_alerts(received_at);

CREATE TABLE IF NOT EXISTS honeypot_block_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    instance_id INTEGER NOT NULL REFERENCES honeypot_instances(id) ON DELETE CASCADE,
    service_name TEXT NOT NULL,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    lateral_movement INTEGER DEFAULT 0,
    port_scanner INTEGER DEFAULT 0,
    UNIQUE(ip_address, instance_id, service_name)
);

CREATE INDEX IF NOT EXISTS idx_honeypot_blocks_ip ON honeypot_block_entries(ip_address);

CREATE TABLE IF NOT EXISTS dns_block_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    dns_server TEXT NOT NULL,
    refresh_interval INTEGER NOT NULL DEFAULT 300,
    stale_cleanup INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_refresh_time TIMESTAMP,
    last_refresh_status TEXT DEFAULT 'pending',
    last_refresh_ip_count INTEGER DEFAULT 0,
    last_refresh_duration REAL,
    consecutive_failures INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dns_resolved_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dns_block_entry_id INTEGER NOT NULL REFERENCES dns_block_entries(id) ON DELETE CASCADE,
    ip_address TEXT NOT NULL,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(dns_block_entry_id, ip_address)
);

CREATE INDEX IF NOT EXISTS idx_dns_resolved_ips_entry_id ON dns_resolved_ips(dns_block_entry_id);
CREATE INDEX IF NOT EXISTS idx_dns_resolved_ips_ip ON dns_resolved_ips(ip_address);
"""


def init_db(db_path=None):
    """Initialize the database: create tables, seed default admin user and app settings.

    Args:
        db_path: Path to the SQLite database file. Defaults to Config.DATABASE_PATH.
    """
    if db_path is None:
        db_path = Config.DATABASE_PATH

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        conn.executescript(SCHEMA_SQL)

        # Migrate existing databases: add new columns if missing
        cursor = conn.execute("PRAGMA table_info(managed_devices)")
        existing_cols = {row[1] for row in cursor.fetchall()}
        if "friendly_name" not in existing_cols:
            conn.execute("ALTER TABLE managed_devices ADD COLUMN friendly_name TEXT DEFAULT ''")
        if "ssh_key" not in existing_cols:
            conn.execute("ALTER TABLE managed_devices ADD COLUMN ssh_key TEXT DEFAULT ''")
        if "sudo_password" not in existing_cols:
            conn.execute("ALTER TABLE managed_devices ADD COLUMN sudo_password TEXT DEFAULT ''")

        # Multi-device support: add new columns for new device types
        cursor = conn.execute("PRAGMA table_info(managed_devices)")
        existing_cols = {row[1] for row in cursor.fetchall()}
        if "enable_password" not in existing_cols:
            conn.execute("ALTER TABLE managed_devices ADD COLUMN enable_password TEXT DEFAULT ''")
        if "group_name" not in existing_cols:
            conn.execute("ALTER TABLE managed_devices ADD COLUMN group_name TEXT DEFAULT 'SOC_BLOCKLIST'")
        if "api_port" not in existing_cols:
            conn.execute("ALTER TABLE managed_devices ADD COLUMN api_port INTEGER DEFAULT 443")

        # Multi-device support: update CHECK constraints for device_type and block_method
        # SQLite doesn't support ALTER CONSTRAINT, so recreate the table
        # Check if migration is needed by inspecting the table definition
        table_sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='managed_devices'"
        ).fetchone()[0]
        needs_constraint_migration = "'cisco_ios'" not in table_sql

        if needs_constraint_migration:
            # Disable foreign keys during table recreation to avoid FK violations
            conn.execute("PRAGMA foreign_keys=OFF")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS managed_devices_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT NOT NULL,
                    device_type TEXT NOT NULL CHECK(device_type IN (
                        'pfsense', 'linux', 'cisco_ios', 'cisco_asa',
                        'fortinet', 'palo_alto', 'unifi'
                    )),
                    status TEXT DEFAULT 'unknown',
                    last_checked TIMESTAMP,
                    web_username TEXT,
                    web_password TEXT,
                    block_method TEXT CHECK(block_method IN (
                        'null_route', 'floating_rule', 'alias_only'
                    )),
                    ssh_port INTEGER DEFAULT 22,
                    ssh_username TEXT,
                    ssh_password TEXT,
                    ssh_key_path TEXT,
                    friendly_name TEXT DEFAULT '',
                    ssh_key TEXT DEFAULT '',
                    sudo_password TEXT DEFAULT '',
                    enable_password TEXT DEFAULT '',
                    group_name TEXT DEFAULT 'SOC_BLOCKLIST',
                    api_port INTEGER DEFAULT 443
                )
            """)
            conn.execute("""
                INSERT INTO managed_devices_new (
                    id, hostname, device_type, status, last_checked,
                    web_username, web_password, block_method,
                    ssh_port, ssh_username, ssh_password, ssh_key_path,
                    friendly_name, ssh_key, sudo_password,
                    enable_password, group_name, api_port
                )
                SELECT
                    id, hostname, device_type, status, last_checked,
                    web_username, web_password, block_method,
                    ssh_port, ssh_username, ssh_password, ssh_key_path,
                    friendly_name, ssh_key, sudo_password,
                    enable_password, group_name, api_port
                FROM managed_devices
            """)
            conn.execute("DROP TABLE managed_devices")
            conn.execute("ALTER TABLE managed_devices_new RENAME TO managed_devices")
            conn.execute("PRAGMA foreign_keys=ON")

        # Cloud provider support: add new columns for cloud device types
        cursor = conn.execute("PRAGMA table_info(managed_devices)")
        existing_cols = {row[1] for row in cursor.fetchall()}
        if "cloud_credentials" not in existing_cols:
            conn.execute("ALTER TABLE managed_devices ADD COLUMN cloud_credentials TEXT DEFAULT ''")
        if "cloud_region" not in existing_cols:
            conn.execute("ALTER TABLE managed_devices ADD COLUMN cloud_region TEXT DEFAULT ''")
        if "cloud_resource_id" not in existing_cols:
            conn.execute("ALTER TABLE managed_devices ADD COLUMN cloud_resource_id TEXT DEFAULT ''")

        # Cloud provider support: update CHECK constraints to include cloud device types and cloud_api block method
        table_sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='managed_devices'"
        ).fetchone()[0]
        needs_cloud_migration = "'aws_waf'" not in table_sql

        if needs_cloud_migration:
            conn.execute("PRAGMA foreign_keys=OFF")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS managed_devices_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT NOT NULL,
                    device_type TEXT NOT NULL CHECK(device_type IN (
                        'pfsense', 'linux', 'cisco_ios', 'cisco_asa',
                        'fortinet', 'palo_alto', 'unifi',
                        'aws_waf', 'azure_nsg', 'gcp_firewall', 'oci_nsg'
                    )),
                    status TEXT DEFAULT 'unknown',
                    last_checked TIMESTAMP,
                    web_username TEXT,
                    web_password TEXT,
                    block_method TEXT CHECK(block_method IN (
                        'null_route', 'floating_rule', 'alias_only', 'cloud_api'
                    )),
                    ssh_port INTEGER DEFAULT 22,
                    ssh_username TEXT,
                    ssh_password TEXT,
                    ssh_key_path TEXT,
                    friendly_name TEXT DEFAULT '',
                    ssh_key TEXT DEFAULT '',
                    sudo_password TEXT DEFAULT '',
                    enable_password TEXT DEFAULT '',
                    group_name TEXT DEFAULT 'SOC_BLOCKLIST',
                    api_port INTEGER DEFAULT 443,
                    cloud_credentials TEXT DEFAULT '',
                    cloud_region TEXT DEFAULT '',
                    cloud_resource_id TEXT DEFAULT ''
                )
            """)
            conn.execute("""
                INSERT INTO managed_devices_new (
                    id, hostname, device_type, status, last_checked,
                    web_username, web_password, block_method,
                    ssh_port, ssh_username, ssh_password, ssh_key_path,
                    friendly_name, ssh_key, sudo_password,
                    enable_password, group_name, api_port,
                    cloud_credentials, cloud_region, cloud_resource_id
                )
                SELECT
                    id, hostname, device_type, status, last_checked,
                    web_username, web_password, block_method,
                    ssh_port, ssh_username, ssh_password, ssh_key_path,
                    friendly_name, ssh_key, sudo_password,
                    enable_password, group_name, api_port,
                    cloud_credentials, cloud_region, cloud_resource_id
                FROM managed_devices
            """)
            conn.execute("DROP TABLE managed_devices")
            conn.execute("ALTER TABLE managed_devices_new RENAME TO managed_devices")
            conn.execute("PRAGMA foreign_keys=ON")


        # Migrate app_settings: add missing columns for existing databases
        cursor = conn.execute("PRAGMA table_info(app_settings)")
        settings_cols = {row[1] for row in cursor.fetchall()}
        if "protected_ranges" not in settings_cols:
            conn.execute("ALTER TABLE app_settings ADD COLUMN protected_ranges TEXT DEFAULT ''")
        if "concurrency_limit" not in settings_cols:
            conn.execute("ALTER TABLE app_settings ADD COLUMN concurrency_limit INTEGER DEFAULT 10")
        if "max_retry_attempts" not in settings_cols:
            conn.execute("ALTER TABLE app_settings ADD COLUMN max_retry_attempts INTEGER DEFAULT 3")
        if "retry_backoff_base" not in settings_cols:
            conn.execute("ALTER TABLE app_settings ADD COLUMN retry_backoff_base INTEGER DEFAULT 30")
        if "reconciliation_interval" not in settings_cols:
            conn.execute("ALTER TABLE app_settings ADD COLUMN reconciliation_interval INTEGER DEFAULT 900")
        if "audit_retention_days" not in settings_cols:
            conn.execute("ALTER TABLE app_settings ADD COLUMN audit_retention_days INTEGER DEFAULT 90")
        if "honeypot_timeout" not in settings_cols:
            conn.execute("ALTER TABLE app_settings ADD COLUMN honeypot_timeout INTEGER DEFAULT 86400")
        if "honeypot_staleness_threshold" not in settings_cols:
            conn.execute("ALTER TABLE app_settings ADD COLUMN honeypot_staleness_threshold INTEGER DEFAULT 3600")

        # SIEM forwarding: add Elasticsearch and Syslog configuration columns
        if "elastic_enabled" not in settings_cols:
            conn.execute("ALTER TABLE app_settings ADD COLUMN elastic_enabled INTEGER DEFAULT 0")
        if "elastic_host" not in settings_cols:
            conn.execute("ALTER TABLE app_settings ADD COLUMN elastic_host TEXT")
        if "elastic_index" not in settings_cols:
            conn.execute("ALTER TABLE app_settings ADD COLUMN elastic_index TEXT DEFAULT 'honeypot-alerts'")
        if "elastic_api_key" not in settings_cols:
            conn.execute("ALTER TABLE app_settings ADD COLUMN elastic_api_key TEXT")
        if "elastic_tls_verify" not in settings_cols:
            conn.execute("ALTER TABLE app_settings ADD COLUMN elastic_tls_verify INTEGER DEFAULT 1")
        if "syslog_enabled" not in settings_cols:
            conn.execute("ALTER TABLE app_settings ADD COLUMN syslog_enabled INTEGER DEFAULT 0")
        if "syslog_host" not in settings_cols:
            conn.execute("ALTER TABLE app_settings ADD COLUMN syslog_host TEXT")
        if "syslog_port" not in settings_cols:
            conn.execute("ALTER TABLE app_settings ADD COLUMN syslog_port INTEGER DEFAULT 514")
        if "syslog_protocol" not in settings_cols:
            conn.execute("ALTER TABLE app_settings ADD COLUMN syslog_protocol TEXT DEFAULT 'udp'")
        if "syslog_facility" not in settings_cols:
            conn.execute("ALTER TABLE app_settings ADD COLUMN syslog_facility TEXT DEFAULT 'local0'")

        # Migrate honeypot_alerts: add raw_payload column for storing full event data
        cursor = conn.execute("PRAGMA table_info(honeypot_alerts)")
        ha_cols = {row[1] for row in cursor.fetchall()}
        if ha_cols and "raw_payload" not in ha_cols:
            conn.execute("ALTER TABLE honeypot_alerts ADD COLUMN raw_payload TEXT")

        # Migrate push_statuses: add retry_count column and update CHECK constraint
        cursor = conn.execute("PRAGMA table_info(push_statuses)")
        ps_cols = {row[1] for row in cursor.fetchall()}
        if "retry_count" not in ps_cols:
            # Recreate table to update CHECK constraint and add retry_count
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS push_statuses_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    block_entry_id INTEGER NOT NULL REFERENCES block_entries(id) ON DELETE CASCADE,
                    device_id INTEGER NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
                    status TEXT NOT NULL CHECK(status IN ('pending', 'in_progress', 'success', 'failed', 'retrying')),
                    error_message TEXT,
                    retry_count INTEGER DEFAULT 0,
                    pushed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(block_entry_id, device_id)
                );
                INSERT INTO push_statuses_new (id, block_entry_id, device_id, status, error_message, pushed_at)
                    SELECT id, block_entry_id, device_id, status, error_message, pushed_at FROM push_statuses;
                DROP TABLE push_statuses;
                ALTER TABLE push_statuses_new RENAME TO push_statuses;
            """)

        # Seed default admin user if not exists
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (Config.DEFAULT_ADMIN_USER,),
        ).fetchone()
        if existing is None:
            password_hash = generate_password_hash(Config.DEFAULT_ADMIN_PASSWORD, method="pbkdf2:sha256")
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (Config.DEFAULT_ADMIN_USER, password_hash),
            )

        # Seed default app_settings if not exists
        existing_settings = conn.execute(
            "SELECT id FROM app_settings WHERE id = 1"
        ).fetchone()
        if existing_settings is None:
            conn.execute(
                "INSERT INTO app_settings (id, monitor_interval, default_block_method) VALUES (1, ?, ?)",
                (Config.MONITOR_INTERVAL, Config.DEFAULT_BLOCK_METHOD),
            )

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


class ConnectionPool:
    """Simple SQLite connection pool using a semaphore to limit concurrency.

    Each connection is created fresh with WAL mode, busy_timeout, and foreign keys enabled.
    """

    def __init__(self, db_path=None, max_connections=5):
        self.db_path = db_path or Config.DATABASE_PATH
        self._semaphore = threading.Semaphore(max_connections)

    @contextmanager
    def get_connection(self):
        """Acquire a pooled connection. Blocks if max_connections are in use."""
        self._semaphore.acquire()
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
            self._semaphore.release()


@contextmanager
def get_db(db_path=None):
    """Context manager that yields a SQLite connection with transaction support.

    Commits on successful exit, rolls back on exception. Foreign keys are enabled.

    Args:
        db_path: Path to the SQLite database file. Defaults to Config.DATABASE_PATH.

    Yields:
        sqlite3.Connection with row_factory set to sqlite3.Row.
    """
    if db_path is None:
        db_path = Config.DATABASE_PATH

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
