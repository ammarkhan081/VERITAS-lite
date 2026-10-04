"""Database connection factory for VERITAS-lite.

SQLite remains the zero-configuration local-development database. Deployments
can set ``DATABASE_URL`` to PostgreSQL for durable, shared campaign storage.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from typing import Any

from backend.core.config import get_settings

_lock = threading.Lock()
_conn: Any | None = None


class _PostgresConnection:
    """Small SQLite-shaped adapter for the project's existing SQL operations."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection
        self._explicit_transaction = False

    def execute(self, query: str, parameters: tuple[Any, ...] = ()) -> Any:
        normalized = query.strip()
        if normalized.upper() == "BEGIN IMMEDIATE":
            normalized = "BEGIN"
            self._explicit_transaction = True
        normalized = normalized.replace("?", "%s")
        return self._connection.execute(normalized, parameters)

    def commit(self) -> None:
        if self._explicit_transaction:
            self._connection.execute("COMMIT")
            self._explicit_transaction = False

    def rollback(self) -> None:
        if self._explicit_transaction:
            self._connection.execute("ROLLBACK")
            self._explicit_transaction = False

    def close(self) -> None:
        self._connection.close()


def uses_postgres() -> bool:
    """Return whether the configured database URL selects PostgreSQL."""
    return get_settings().database_url.startswith(("postgres://", "postgresql://"))


def get_db() -> Any:
    """Return a process-wide connection for the configured database."""
    global _conn
    if _conn is None:
        with _lock:
            if _conn is None:
                settings = get_settings()
                if settings.database_url.startswith(("postgres://", "postgresql://")):
                    import psycopg
                    from psycopg.rows import dict_row

                    database_url = settings.database_url
                    if database_url.startswith("postgres://"):
                        database_url = "postgresql://" + database_url[len("postgres://") :]
                    connection = psycopg.connect(
                        database_url,
                        autocommit=True,
                        row_factory=dict_row,
                        connect_timeout=10,
                    )
                    _conn = _PostgresConnection(connection)
                else:
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
        schema = f.read()
    if uses_postgres():
        for statement in schema.split(";"):
            if statement.strip():
                conn.execute(statement)
        _apply_postgres_column_migrations(conn)
    else:
        conn.executescript(schema)
        _apply_sqlite_column_migrations(conn)
    conn.commit()


# Columns added after the initial schema. ``CREATE TABLE IF NOT EXISTS`` does not
# alter tables that already exist, so older database files are upgraded here.
_COLUMN_MIGRATIONS: tuple[tuple[str, str, str], ...] = (
    ("attacks", "task", "TEXT NOT NULL DEFAULT ''"),
    ("held_out_attacks", "task", "TEXT NOT NULL DEFAULT ''"),
)


def _apply_sqlite_column_migrations(conn: sqlite3.Connection) -> None:
    """Add any missing columns listed in ``_COLUMN_MIGRATIONS`` (idempotent)."""
    for table, column, definition in _COLUMN_MIGRATIONS:
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _apply_postgres_column_migrations(conn: Any) -> None:
    """Add any missing columns listed in ``_COLUMN_MIGRATIONS`` idempotently."""
    for table, column, definition in _COLUMN_MIGRATIONS:
        existing = {
            row["column_name"]
            for row in conn.execute(
                """
                SELECT column_name FROM information_schema.columns
                WHERE table_schema = current_schema() AND table_name = ?
                """,
                (table,),
            )
        }
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def reset_db() -> None:
    """Close the shared connection so local callers can reconfigure storage."""
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
            _conn = None
