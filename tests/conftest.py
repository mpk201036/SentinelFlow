"""Shared pytest fixtures.

Tests must never depend on the developer's local ``.env`` file or exported
environment variables, so every fixture here builds isolated settings.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.core.logging import reset_logging
from app.database.init_db import initialize_database
from app.database.session import create_db_engine, get_engine, reset_engine

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Remove every SENTINELFLOW_* variable from the environment."""
    import os

    for key in list(os.environ):
        if key.upper().startswith("SENTINELFLOW_"):
            monkeypatch.delenv(key, raising=False)
    get_settings.cache_clear()
    return monkeypatch


@pytest.fixture
def settings(clean_env: pytest.MonkeyPatch) -> Settings:
    """Default settings, isolated from any .env file on disk."""
    return Settings(_env_file=None)


@pytest.fixture(autouse=True)
def _isolate_logging() -> Iterator[None]:
    """Guarantee each test starts and ends without SentinelFlow log handlers."""
    reset_logging()
    previous_level = logging.getLogger().level
    yield
    reset_logging()
    logging.getLogger().setLevel(previous_level)


@pytest.fixture
def project_root() -> Path:
    return PROJECT_ROOT


# ---------------------------------------------------------------------------
# Database fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def db_settings(tmp_path: Path, clean_env: pytest.MonkeyPatch) -> Settings:
    """Settings pointing at a throwaway SQLite file.

    A real file rather than ``:memory:`` on purpose: the pragmas under test
    (foreign keys, WAL) only behave realistically against a file.
    """
    return Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'test.db'}")


@pytest.fixture
def db_engine(db_settings: Settings) -> Iterator[Engine]:
    engine = create_db_engine(db_settings)
    initialize_database(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine: Engine) -> Iterator[Session]:
    factory = sessionmaker(bind=db_engine, expire_on_commit=False, autoflush=False)
    session = factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def global_db(db_settings: Settings) -> Iterator[Settings]:
    """Point the process-wide engine at a throwaway database.

    Needed by anything that goes through ``session_scope`` or the FastAPI
    dependency, both of which use the module-level singleton rather than an
    injected engine.
    """
    reset_engine()
    initialize_database(get_engine(db_settings))
    yield db_settings
    reset_engine()
