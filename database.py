"""SQLite database initialization and connection helpers for SOC IP Blocker."""

import sqlite3
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
    device_type TEXT NOT NULL CHECK(device_type IN ('pfsense', 'linux')),
    status TEXT DEFAULT 'unknown',
    last_checked TIMESTAMP,
    web_username TEXT,
    web_password TEXT,
    block_method TEXT CHECK(block_method IN ('null_route', 'floating_rule')),
    ssh_port INTEGER DEFAULT 22,
    ssh_username TEXT,
    ssh_password TEXT,
    ssh_key_path TEXT,
    friendly_name TEXT DEFAULT '',
    ssh_key TEXT DEFAULT '',
    sudo_password TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS push_statuses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    block_entry_id INTEGER NOT NULL REFERENCES block_entries(id) ON DELETE CASCADE,
    device_id INTEGER NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK(status IN ('success', 'failed', 'pending')),
    error_message TEXT,
    pushed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(block_entry_id, device_id)
);

CREATE TABLE IF NOT EXISTS app_settings (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    monitor_interval INTEGER DEFAULT 300,
    default_block_method TEXT DEFAULT 'floating_rule',
    protected_ranges TEXT DEFAULT ''
);
"""


def init_db(db_path=None):
    """Initialize the database: create tables, seed default admin user and app settings.

    Args:
        db_path: Path to the SQLite database file. Defaults to Config.DATABASE_PATH.
    """
    if db_path is None:
        db_path = Config.DATABASE_PATH

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
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

        # Migrate app_settings: add protected_ranges column if missing
        cursor = conn.execute("PRAGMA table_info(app_settings)")
        settings_cols = {row[1] for row in cursor.fetchall()}
        if "protected_ranges" not in settings_cols:
            conn.execute("ALTER TABLE app_settings ADD COLUMN protected_ranges TEXT DEFAULT ''")

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
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
