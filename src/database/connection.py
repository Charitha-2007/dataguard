"""Database connection manager for DataGuard.

Provides thread-safe connection handling, dictionary-like row access,
and foreign key constraint enforcement for SQLite.
"""

import sqlite3
from contextlib import contextmanager
from typing import Generator
from config.settings import DATABASE_PATH


def get_connection() -> sqlite3.Connection:
    """Creates and configures a new SQLite connection.

    Enables:
    - Row factory as sqlite3.Row (column access by name)
    - Foreign key constraints (disabled by default in SQLite)
    - WAL (Write-Ahead Logging) journal mode for better concurrent read/write performance
    """
    conn = sqlite3.connect(DATABASE_PATH, timeout=20.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Context manager for safe database operations.

    Automatically commits successful transactions, rolls back if an error occurs,
    and guarantees the connection is properly closed.

    Usage:
        with get_db() as conn:
            conn.execute("INSERT INTO ...")
    """
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
