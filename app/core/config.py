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
* When AI is enabled, alert evidence is sent only to a model on this machine.
  A provider URL that points anywhere else is refused unless
  ``ai_allow_remote_provider`` is set, because evidence routinely contains
  usernames, hostnames and internal addresses.
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


def is_loopback_host(host: str) -> bool:
    """Whether a bind address accepts connections only from this machine.

    The whole of 127.0.0.0/8 and ::1 count, as does "localhost". Anything
    else - including 0.0.0.0, which means every interface - does not.
    """
    import ipaddress

    candidate = host.strip().strip("[]").lower()
    if candidate == "localhost":
        return True
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def _default_analyst() -> str:
    """The local account name, as a sensible default for a single-analyst tool."""
    import getpass

    try:
        name = getpass.getuser()
    except Exception:  # no login name in some containers
        return "analyst"
    cleaned = "".join(ch for ch in name if ch.isprintable()).strip()[:64]
    return cleaned or "analyst"


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
    #: Requests per minute, per client address. A coarse guard against a
    #: runaway importer, not a substitute for a gateway in front of a real
    #: deployment: it is per-process and resets when the process does.
    api_rate_limit_per_minute: Annotated[int, Field(ge=0, le=100_000)] = 600
    #: Interactive OpenAPI docs at /docs. Useful locally; turn off if the API
    #: is ever exposed, since it enumerates every endpoint.
    api_docs_enabled: bool = True
    #: Largest page any list endpoint will return.
    api_max_page_size: Annotated[int, Field(ge=1, le=1_000)] = 200

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
    # Analyst identity
    # ------------------------------------------------------------------
    #: Recorded as the author of every decision, note and audit entry an
    #: analyst makes. SentinelFlow has no authentication, so this is
    #: attribution for a single local analyst, not proof of identity.
    analyst_name: Annotated[str, Field(min_length=1, max_length=64)] = Field(
        default_factory=_default_analyst
    )

    # ------------------------------------------------------------------
    # Optional AI (advisory only, never authoritative)
    # ------------------------------------------------------------------
    ai_enabled: bool = False
    ai_provider: AIProvider = AIProvider.NONE
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: Annotated[str, Field(min_length=1, max_length=128)] = "llama3.1:8b"
    ai_timeout_seconds: Annotated[int, Field(ge=1, le=600)] = 60
    #: Off by default. Evidence leaves the machine only if this is set.
    ai_allow_remote_provider: bool = False

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

    @field_validator("analyst_name", mode="before")
    @classmethod
    def _clean_analyst_name(cls, value: Any) -> str:
        text = "".join(ch for ch in str(value) if ch.isprintable()).strip()
        if not text:
            raise ValueError("analyst_name cannot be blank")
        return text

    @field_validator("ollama_base_url", mode="after")
    @classmethod
    def _validate_provider_url(cls, value: str) -> str:
        """Accept a plain http(s) origin and nothing else.

        Credentials in the URL would end up in logs and in ``config`` output,
        and a query string or fragment has no meaning for the Ollama API, so
        both are refused rather than silently carried along.
        """
        from urllib.parse import urlsplit

        url = value.strip().rstrip("/")
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ValueError("ollama_base_url must use http or https")
        if not parts.hostname:
            raise ValueError("ollama_base_url must include a host")
        if parts.username or parts.password:
            raise ValueError("ollama_base_url must not contain credentials")
        if parts.query or parts.fragment:
            raise ValueError("ollama_base_url must not contain a query or fragment")
        return url

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
    def context_file(self) -> Path:
        """Environment context used by the severity engine."""
        return PROJECT_ROOT / "data" / "context" / "environment.yaml"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ai_active(self) -> bool:
        """True only when AI is both enabled *and* a real provider is chosen.

        Every AI call site checks this. When it is False, SentinelFlow performs
        no network calls and no model is ever contacted.
        """
        return self.ai_enabled and self.ai_provider is not AIProvider.NONE

    @property
    def ai_endpoint_problem(self) -> str | None:
        """Why the configured provider must not be contacted, or None if it may.

        Checked every time a provider is built, so a remote URL is refused
        whether AI was enabled from the environment, a ``.env`` file or code.
        """
        from urllib.parse import urlsplit

        host = urlsplit(self.ollama_base_url).hostname or ""
        if not is_loopback_host(host) and not self.ai_allow_remote_provider:
            return (
                f"the AI provider at {host!r} is not on this machine, and alert evidence "
                "would be sent to it. Set SENTINELFLOW_AI_ALLOW_REMOTE_PROVIDER=true "
                "to allow that deliberately."
            )
        return None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_production(self) -> bool:
        return self.environment is Environment.PRODUCTION

    @computed_field  # type: ignore[prop-decorator]
    @property
    def api_is_exposed(self) -> bool:
        """True when the API would accept connections from another machine.

        SentinelFlow has no authentication, so this is worth saying out loud at
        startup rather than discovering later.
        """
        return not is_loopback_host(self.api_host)

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
            "api_rate_limit_per_minute": self.api_rate_limit_per_minute,
            "api_docs_enabled": self.api_docs_enabled,
            "log_level": self.log_level,
            "log_format": self.log_format.value,
            "log_file": str(self.log_file) if self.log_file else None,
            "analyst_name": self.analyst_name,
            "ai_enabled": self.ai_enabled,
            "ai_provider": self.ai_provider.value,
            "ai_active": self.ai_active,
            "ai_model": self.ollama_model,
            "ai_allow_remote_provider": self.ai_allow_remote_provider,
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
