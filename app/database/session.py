"""Engine and session management.

One SQLite behaviour deserves to be called out, because relying on the default
would make half the schema decorative: **SQLite does not enforce foreign keys
unless you ask it to, on every connection.** ``PRAGMA foreign_keys=ON`` is set
in a connect listener below. Without it, a detection could reference an alert
that does not exist and nothing would complain.

Two other pragmas matter in practice:

* ``journal_mode=WAL`` lets the dashboard read while an import is writing,
  instead of the reader getting "database is locked".
* ``busy_timeout`` makes a concurrent writer wait briefly rather than fail
  immediately.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def _configure_sqlite(dbapi_connection: Any, _record: Any) -> None:
    """Apply per-connection pragmas. SQLite forgets these between connections."""
    if not isinstance(dbapi_connection, sqlite3.Connection):
        return  # pragma: no cover - only relevant if the backend is swapped
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=5000")
    finally:
        cursor.close()


def _sqlite_path(database_url: str) -> Path | None:
    """Filesystem path behind a SQLite URL, or ``None`` for in-memory."""
    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        return None
    raw = database_url[len(prefix) :]
    if raw in ("", ":memory:") or raw.startswith(":memory:"):
        return None
    return Path(raw)


def _owner_only(path: Path) -> None:
    """Make the database file readable and writable by its owner alone.

    It holds everything ingested - usernames, hosts, command lines, analyst
    notes - and under the usual umask it would be readable by every account on
    the machine. It is created with owner-only permissions before SQLite opens
    it (an empty file is a valid empty database), and an existing file is
    tightened. SQLite gives its -wal and -shm files the database's permissions.
    """
    if os.name != "posix":  # pragma: no cover - Windows uses ACLs, not mode bits
        return
    if not path.exists():
        os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
    elif path.stat().st_mode & 0o077:
        logger.info("restricting %s to its owner", path)
        path.chmod(0o600)


def create_db_engine(settings: Settings | None = None, *, echo: bool = False) -> Engine:
    """Build an engine with SQLite pragmas attached."""
    settings = settings or get_settings()
    url = settings.database_url

    path = _sqlite_path(url)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        _owner_only(path)

    engine = create_engine(
        url,
        echo=echo,
        future=True,
        # check_same_thread=False is required because FastAPI serves requests
        # from a thread pool; connection use is still serialised by the pool.
        connect_args={"check_same_thread": False} if url.startswith("sqlite") else {},
    )
    if url.startswith("sqlite"):
        event.listen(engine, "connect", _configure_sqlite)
    return engine


def get_engine(settings: Settings | None = None) -> Engine:
    """Return the process-wide engine, creating it on first use."""
    global _engine
    if _engine is None:
        _engine = create_db_engine(settings)
        logger.debug("database engine created")
    return _engine


def get_session_factory(settings: Settings | None = None) -> sessionmaker[Session]:
    """Return the process-wide session factory."""
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(
            bind=get_engine(settings), expire_on_commit=False, autoflush=False
        )
    return _session_factory


@contextmanager
def session_scope(settings: Settings | None = None) -> Iterator[Session]:
    """Transactional scope: commit on success, roll back on any exception."""
    session = get_session_factory(settings)()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db_session() -> Iterator[Session]:
    """FastAPI dependency yielding a session per request."""
    with session_scope() as session:
        yield session


def reset_engine() -> None:
    """Dispose of the engine and session factory. Used by tests and the CLI."""
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None
