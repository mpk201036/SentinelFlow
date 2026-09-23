"""Shared pytest fixtures.

Tests must never depend on the developer's local ``.env`` file or exported
environment variables, so every fixture here builds isolated settings.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.core.config import Settings, get_settings
from app.core.logging import reset_logging

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
