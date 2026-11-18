"""Database connection manager for DataGuard.

Provides thread-safe connection handling, dictionary-like row access,
and foreign key constraint enforcement for SQLite.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional
from config.settings import DATABASE_PATH

# Active database path (can be changed to test_dataguard.db during automated testing)
_CURRENT_DB_PATH: Path = DATABASE_PATH


def set_database_path(path: Path) -> None:
    """Switches the active database file (e.g. for isolated test suites)."""
    global _CURRENT_DB_PATH
    _CURRENT_DB_PATH = path


def get_current_database_path() -> Path:
    """Returns the currently active database path."""
    return _CURRENT_DB_PATH


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Creates and configures a new SQLite connection.

    Enables:
    - Row factory as sqlite3.Row (column access by name)
    - Foreign key constraints (disabled by default in SQLite)
    - WAL (Write-Ahead Logging) journal mode for better concurrent read/write performance
    """
    target = db_path or _CURRENT_DB_PATH
    conn = sqlite3.connect(target, timeout=20.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


@contextmanager
def get_db(db_path: Optional[Path] = None) -> Generator[sqlite3.Connection, None, None]:
    """Context manager for safe database operations.

    Automatically commits successful transactions, rolls back if an error occurs,
    and guarantees the connection is properly closed.

    Usage:
        with get_db() as conn:
            conn.execute("INSERT INTO ...")
    """
    conn = get_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
