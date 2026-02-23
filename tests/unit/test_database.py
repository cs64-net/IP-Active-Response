"""Unit tests for database.py — schema initialization and connection helpers."""

import os
import sqlite3
import tempfile

import pytest
from werkzeug.security import check_password_hash

from config import Config
from database import get_db, init_db


@pytest.fixture
def db_path(tmp_path):
    """Provide a temporary database path for each test."""
    return str(tmp_path / "test.db")


class TestInitDb:
    """Tests for init_db() function."""

    def test_creates_all_tables(self, db_path):
        init_db(db_path)
        conn = sqlite3.connect(db_path)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
        conn.close()
        assert tables == {"users", "block_entries", "managed_devices", "push_statuses", "app_settings"}

    def test_seeds_default_admin_user(self, db_path):
        init_db(db_path)
        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT username, password_hash FROM users WHERE username = ?",
            (Config.DEFAULT_ADMIN_USER,),
        ).fetchone()
        conn.close()
        assert row is not None
        assert row[0] == Config.DEFAULT_ADMIN_USER
        assert check_password_hash(row[1], Config.DEFAULT_ADMIN_PASSWORD)

    def test_admin_password_is_hashed_not_plaintext(self, db_path):
        init_db(db_path)
        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (Config.DEFAULT_ADMIN_USER,),
        ).fetchone()
        conn.close()
        assert row[0] != Config.DEFAULT_ADMIN_PASSWORD

    def test_seeds_default_app_settings(self, db_path):
        init_db(db_path)
        conn = sqlite3.connect(db_path)
        row = conn.execute("SELECT * FROM app_settings WHERE id = 1").fetchone()
        conn.close()
        assert row is not None
        assert row[1] == Config.MONITOR_INTERVAL
        assert row[2] == Config.DEFAULT_BLOCK_METHOD

    def test_idempotent_multiple_calls(self, db_path):
        init_db(db_path)
        init_db(db_path)
        conn = sqlite3.connect(db_path)
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        settings_count = conn.execute("SELECT COUNT(*) FROM app_settings").fetchone()[0]
        conn.close()
        assert user_count == 1
        assert settings_count == 1

    def test_foreign_keys_enabled_during_init(self, db_path):
        init_db(db_path)
        # Verify foreign key constraints work by trying an invalid insert
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO push_statuses (block_entry_id, device_id, status) VALUES (999, 999, 'pending')"
            )
        conn.close()

    def test_uses_default_path_when_none(self, monkeypatch, tmp_path):
        test_path = str(tmp_path / "default.db")
        monkeypatch.setattr(Config, "DATABASE_PATH", test_path)
        init_db()
        assert os.path.exists(test_path)


class TestGetDb:
    """Tests for get_db() context manager."""

    def test_yields_connection_with_row_factory(self, db_path):
        init_db(db_path)
        with get_db(db_path) as conn:
            row = conn.execute("SELECT * FROM app_settings WHERE id = 1").fetchone()
            # sqlite3.Row supports key-based access
            assert row["monitor_interval"] == Config.MONITOR_INTERVAL

    def test_commits_on_success(self, db_path):
        init_db(db_path)
        with get_db(db_path) as conn:
            conn.execute(
                "INSERT INTO block_entries (ip_address, added_by) VALUES (?, ?)",
                ("10.0.0.1", "testuser"),
            )
        # Verify data persisted
        with get_db(db_path) as conn:
            row = conn.execute(
                "SELECT ip_address FROM block_entries WHERE ip_address = '10.0.0.1'"
            ).fetchone()
            assert row is not None

    def test_rolls_back_on_exception(self, db_path):
        init_db(db_path)
        with pytest.raises(ValueError):
            with get_db(db_path) as conn:
                conn.execute(
                    "INSERT INTO block_entries (ip_address, added_by) VALUES (?, ?)",
                    ("10.0.0.2", "testuser"),
                )
                raise ValueError("Simulated failure")
        # Verify data was NOT persisted
        with get_db(db_path) as conn:
            row = conn.execute(
                "SELECT ip_address FROM block_entries WHERE ip_address = '10.0.0.2'"
            ).fetchone()
            assert row is None

    def test_foreign_keys_enabled(self, db_path):
        init_db(db_path)
        with get_db(db_path) as conn:
            fk_status = conn.execute("PRAGMA foreign_keys").fetchone()[0]
            assert fk_status == 1

    def test_uses_default_path_when_none(self, monkeypatch, tmp_path):
        test_path = str(tmp_path / "default.db")
        monkeypatch.setattr(Config, "DATABASE_PATH", test_path)
        init_db(test_path)
        with get_db() as conn:
            row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
            assert row[0] == 1

    def test_connection_closed_after_context(self, db_path):
        init_db(db_path)
        with get_db(db_path) as conn:
            pass
        # Connection should be closed — attempting to use it should fail
        with pytest.raises(Exception):
            conn.execute("SELECT 1")


class TestSchemaConstraints:
    """Tests for database schema constraints."""

    def test_unique_username(self, db_path):
        init_db(db_path)
        with get_db(db_path) as conn:
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (Config.DEFAULT_ADMIN_USER, "somehash"),
                )

    def test_unique_ip_address(self, db_path):
        init_db(db_path)
        with get_db(db_path) as conn:
            conn.execute(
                "INSERT INTO block_entries (ip_address, added_by) VALUES ('1.2.3.4', 'user1')"
            )
        with pytest.raises(sqlite3.IntegrityError):
            with get_db(db_path) as conn:
                conn.execute(
                    "INSERT INTO block_entries (ip_address, added_by) VALUES ('1.2.3.4', 'user2')"
                )

    def test_device_type_check_constraint(self, db_path):
        init_db(db_path)
        with pytest.raises(sqlite3.IntegrityError):
            with get_db(db_path) as conn:
                conn.execute(
                    "INSERT INTO managed_devices (hostname, device_type) VALUES ('host1', 'invalid')"
                )

    def test_push_status_check_constraint(self, db_path):
        init_db(db_path)
        with get_db(db_path) as conn:
            conn.execute(
                "INSERT INTO block_entries (ip_address, added_by) VALUES ('5.5.5.5', 'admin')"
            )
            conn.execute(
                "INSERT INTO managed_devices (hostname, device_type) VALUES ('fw1', 'pfsense')"
            )
        with pytest.raises(sqlite3.IntegrityError):
            with get_db(db_path) as conn:
                conn.execute(
                    "INSERT INTO push_statuses (block_entry_id, device_id, status) VALUES (1, 1, 'invalid_status')"
                )

    def test_cascade_delete_block_entry_removes_push_statuses(self, db_path):
        init_db(db_path)
        with get_db(db_path) as conn:
            conn.execute(
                "INSERT INTO block_entries (ip_address, added_by) VALUES ('6.6.6.6', 'admin')"
            )
            conn.execute(
                "INSERT INTO managed_devices (hostname, device_type) VALUES ('fw1', 'pfsense')"
            )
            conn.execute(
                "INSERT INTO push_statuses (block_entry_id, device_id, status) VALUES (1, 1, 'success')"
            )
        with get_db(db_path) as conn:
            conn.execute("DELETE FROM block_entries WHERE ip_address = '6.6.6.6'")
        with get_db(db_path) as conn:
            count = conn.execute("SELECT COUNT(*) FROM push_statuses").fetchone()[0]
            assert count == 0

    def test_app_settings_single_row_constraint(self, db_path):
        init_db(db_path)
        with pytest.raises(sqlite3.IntegrityError):
            with get_db(db_path) as conn:
                conn.execute(
                    "INSERT INTO app_settings (id, monitor_interval, default_block_method) VALUES (2, 60, 'null_route')"
                )

    def test_block_method_check_constraint(self, db_path):
        init_db(db_path)
        with pytest.raises(sqlite3.IntegrityError):
            with get_db(db_path) as conn:
                conn.execute(
                    "INSERT INTO managed_devices (hostname, device_type, block_method) VALUES ('fw1', 'pfsense', 'invalid_method')"
                )
