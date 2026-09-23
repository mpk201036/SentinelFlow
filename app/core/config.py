"""Application configuration.

Configuration is read from environment variables (optionally via a ``.env``
file) using the ``SENTINELFLOW_`` prefix. Every setting has a safe default, so
the application runs correctly with no configuration at all.

Security notes
--------------
* The API binds to ``127.0.0.1`` by default. SentinelFlow processes untrusted
  event data and has no authentication layer, so it must not be exposed to a
  network without a deliberate decision.
* AI is **disabled by default**. The deterministic pipeline is complete without
  it, and the AI can never set an alert's official severity.
* Ingestion limits exist to bound memory use and reject hostile input.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field, computed_field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Project root = the directory containing `app/`, `rules/`, `data/`, ...
PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]


class Environment(StrEnum):
    """Deployment environment."""

    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class LogFormat(StrEnum):
    """Log output format."""

    TEXT = "text"
    JSON = "json"


class AIProvider(StrEnum):
    """Supported AI providers.

    ``NONE`` is the default and means "no model is contacted at all".
    """

    NONE = "none"
    OLLAMA = "ollama"


def _resolve(path: str | Path) -> Path:
    """Resolve a possibly-relative path against the project root."""
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    return candidate.resolve()


class Settings(BaseSettings):
    """Runtime settings for SentinelFlow."""

    model_config = SettingsConfigDict(
        env_prefix="SENTINELFLOW_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------
    app_name: str = "SentinelFlow"
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False

    # ------------------------------------------------------------------
    # Storage
    # ------------------------------------------------------------------
    database_url: str = "sqlite:///data/sentinelflow.db"

    # ------------------------------------------------------------------
    # HTTP server
    # ------------------------------------------------------------------
    api_host: str = "127.0.0.1"
    api_port: Annotated[int, Field(ge=1, le=65535)] = 8000

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    log_level: str = "INFO"
    log_format: LogFormat = LogFormat.TEXT
    log_file: Path | None = None

    # ------------------------------------------------------------------
    # Ingestion limits — all imported data is treated as untrusted
    # ------------------------------------------------------------------
    max_upload_bytes: Annotated[int, Field(ge=1_024, le=512 * 1024 * 1024)] = 10 * 1024 * 1024
    max_events_per_import: Annotated[int, Field(ge=1, le=1_000_000)] = 10_000
    max_field_length: Annotated[int, Field(ge=64, le=1_048_576)] = 8_192

    # ------------------------------------------------------------------
    # Correlation
    # ------------------------------------------------------------------
    correlation_window_minutes: Annotated[int, Field(ge=1, le=1_440)] = 30

    # ------------------------------------------------------------------
    # Optional AI (advisory only, never authoritative)
    # ------------------------------------------------------------------
    ai_enabled: bool = False
    ai_provider: AIProvider = AIProvider.NONE
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.1:8b"
    ai_timeout_seconds: Annotated[int, Field(ge=1, le=600)] = 60

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    @field_validator("log_level", mode="before")
    @classmethod
    def _normalise_log_level(cls, value: Any) -> str:
        level = str(value).strip().upper()
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if level not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}, got {value!r}")
        return level

    @field_validator("database_url", mode="after")
    @classmethod
    def _absolutise_sqlite_path(cls, value: str) -> str:
        """Make relative SQLite paths resolve against the project root.

        Keeps ``sqlite:///data/sentinelflow.db`` working regardless of the
        directory the process was started from.
        """
        prefix = "sqlite:///"
        if not value.startswith(prefix) or value.startswith("sqlite:////"):
            return value
        raw = value[len(prefix) :]
        if raw in ("", ":memory:"):
            return value
        return f"sqlite:///{_resolve(raw)}"

    @field_validator("log_file", mode="after")
    @classmethod
    def _absolutise_log_file(cls, value: Path | None) -> Path | None:
        return _resolve(value) if value is not None else None

    # ------------------------------------------------------------------
    # Derived values
    # ------------------------------------------------------------------
    @computed_field  # type: ignore[prop-decorator]
    @property
    def project_root(self) -> Path:
        return PROJECT_ROOT

    @computed_field  # type: ignore[prop-decorator]
    @property
    def data_dir(self) -> Path:
        return PROJECT_ROOT / "data"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rules_dir(self) -> Path:
        return PROJECT_ROOT / "rules"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def samples_dir(self) -> Path:
        return PROJECT_ROOT / "data" / "samples"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def mitre_dir(self) -> Path:
        return PROJECT_ROOT / "data" / "mitre"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ai_active(self) -> bool:
        """True only when AI is both enabled *and* a real provider is chosen.

        Every AI call site checks this. When it is False, SentinelFlow performs
        no network calls and no model is ever contacted.
        """
        return self.ai_enabled and self.ai_provider is not AIProvider.NONE

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_production(self) -> bool:
        return self.environment is Environment.PRODUCTION

    # ------------------------------------------------------------------
    # Safe display
    # ------------------------------------------------------------------
    def summary(self) -> dict[str, Any]:
        """A human-readable, non-sensitive view of the configuration.

        Used by the CLI and the startup banner. Contains no secrets today, and
        acts as an explicit allow-list so future secret settings cannot leak
        into logs by accident.
        """
        return {
            "app_name": self.app_name,
            "version": _version(),
            "environment": self.environment.value,
            "debug": self.debug,
            "database_url": self.database_url,
            "api": f"{self.api_host}:{self.api_port}",
            "log_level": self.log_level,
            "log_format": self.log_format.value,
            "log_file": str(self.log_file) if self.log_file else None,
            "ai_enabled": self.ai_enabled,
            "ai_provider": self.ai_provider.value,
            "ai_active": self.ai_active,
            "correlation_window_minutes": self.correlation_window_minutes,
            "max_upload_bytes": self.max_upload_bytes,
            "max_events_per_import": self.max_events_per_import,
        }


def _version() -> str:
    from app import __version__

    return __version__


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton.

    Cached so that configuration is read once. Tests that need different values
    should either construct ``Settings(...)`` directly or call
    ``get_settings.cache_clear()`` after patching the environment.
    """
    return Settings()
