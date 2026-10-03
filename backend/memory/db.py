"""SQLite connection factory for VERITAS-lite."""

from __future__ import annotations

import os
import sqlite3
import threading

from backend.core.config import get_settings

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None


def get_db() -> sqlite3.Connection:
    """Return a process-wide SQLite connection with WAL mode enabled."""
    global _conn
    if _conn is None:
        with _lock:
            if _conn is None:
                settings = get_settings()
                os.makedirs(os.path.dirname(settings.database_url) or ".", exist_ok=True)
                _conn = sqlite3.connect(settings.database_url, check_same_thread=False)
                _conn.row_factory = sqlite3.Row
                _conn.execute("PRAGMA journal_mode=WAL;")
                _conn.execute("PRAGMA foreign_keys=ON;")
                _conn.commit()
    return _conn


def init_db() -> None:
    """Create all tables if they don't exist and apply additive column migrations."""
    conn = get_db()
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, encoding="utf-8") as f:
        conn.executescript(f.read())
    _apply_column_migrations(conn)
    conn.commit()


# Columns added after the initial schema. ``CREATE TABLE IF NOT EXISTS`` does not
# alter tables that already exist, so older database files are upgraded here.
_COLUMN_MIGRATIONS: tuple[tuple[str, str, str], ...] = (
    ("attacks", "task", "TEXT NOT NULL DEFAULT ''"),
    ("held_out_attacks", "task", "TEXT NOT NULL DEFAULT ''"),
)


def _apply_column_migrations(conn: sqlite3.Connection) -> None:
    """Add any missing columns listed in ``_COLUMN_MIGRATIONS`` (idempotent)."""
    for table, column, definition in _COLUMN_MIGRATIONS:
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def reset_db() -> None:
    """Close the shared connection so tests can point at a new database file."""
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
            _conn = None
