"""Stage 1 — configuration behaviour."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import PROJECT_ROOT, AIProvider, Environment, LogFormat, Settings, get_settings

pytestmark = pytest.mark.unit


class TestDefaults:
    def test_ai_is_disabled_by_default(self, settings: Settings) -> None:
        """The system must be fully usable with no AI configured."""
        assert settings.ai_enabled is False
        assert settings.ai_provider is AIProvider.NONE
        assert settings.ai_active is False

    def test_api_binds_to_loopback_by_default(self, settings: Settings) -> None:
        """SentinelFlow has no auth layer; exposing it must be deliberate."""
        assert settings.api_host == "127.0.0.1"
        assert settings.api_port == 8000

    def test_sensible_operational_defaults(self, settings: Settings) -> None:
        assert settings.environment is Environment.DEVELOPMENT
        assert settings.debug is False
        assert settings.log_level == "INFO"
        assert settings.log_format is LogFormat.TEXT
        assert settings.log_file is None
        assert settings.correlation_window_minutes == 30

    def test_ingestion_limits_are_bounded(self, settings: Settings) -> None:
        assert settings.max_upload_bytes == 10 * 1024 * 1024
        assert settings.max_events_per_import == 10_000
        assert settings.max_field_length == 8_192

    def test_derived_directories_resolve_under_project_root(self, settings: Settings) -> None:
        assert settings.project_root == PROJECT_ROOT
        assert settings.data_dir == PROJECT_ROOT / "data"
        assert settings.rules_dir == PROJECT_ROOT / "rules"
        assert settings.samples_dir == PROJECT_ROOT / "data" / "samples"
        assert settings.mitre_dir == PROJECT_ROOT / "data" / "mitre"


class TestEnvironmentOverrides:
    def test_prefixed_variables_are_applied(self, clean_env: pytest.MonkeyPatch) -> None:
        clean_env.setenv("SENTINELFLOW_API_PORT", "9100")
        clean_env.setenv("SENTINELFLOW_LOG_LEVEL", "debug")
        clean_env.setenv("SENTINELFLOW_ENVIRONMENT", "test")
        loaded = Settings(_env_file=None)
        assert loaded.api_port == 9100
        assert loaded.log_level == "DEBUG"
        assert loaded.environment is Environment.TEST

    def test_unprefixed_variables_are_ignored(self, clean_env: pytest.MonkeyPatch) -> None:
        """A stray ``DEBUG=true`` in the shell must not reconfigure the app."""
        clean_env.setenv("DEBUG", "true")
        clean_env.setenv("API_PORT", "1")
        loaded = Settings(_env_file=None)
        assert loaded.debug is False
        assert loaded.api_port == 8000

    def test_enabling_ai_requires_a_provider_to_become_active(
        self, clean_env: pytest.MonkeyPatch
    ) -> None:
        clean_env.setenv("SENTINELFLOW_AI_ENABLED", "true")
        assert Settings(_env_file=None).ai_active is False  # provider still "none"

        clean_env.setenv("SENTINELFLOW_AI_PROVIDER", "ollama")
        assert Settings(_env_file=None).ai_active is True


class TestValidation:
    @pytest.mark.parametrize("bad_level", ["verbose", "trace", "", "9"])
    def test_invalid_log_level_is_rejected(
        self, clean_env: pytest.MonkeyPatch, bad_level: str
    ) -> None:
        clean_env.setenv("SENTINELFLOW_LOG_LEVEL", bad_level)
        with pytest.raises(ValidationError):
            Settings(_env_file=None)

    @pytest.mark.parametrize("bad_port", ["0", "70000", "-1"])
    def test_out_of_range_port_is_rejected(
        self, clean_env: pytest.MonkeyPatch, bad_port: str
    ) -> None:
        clean_env.setenv("SENTINELFLOW_API_PORT", bad_port)
        with pytest.raises(ValidationError):
            Settings(_env_file=None)

    def test_unknown_provider_is_rejected(self, clean_env: pytest.MonkeyPatch) -> None:
        clean_env.setenv("SENTINELFLOW_AI_PROVIDER", "openai")
        with pytest.raises(ValidationError):
            Settings(_env_file=None)

    def test_oversized_upload_limit_is_rejected(self, clean_env: pytest.MonkeyPatch) -> None:
        clean_env.setenv("SENTINELFLOW_MAX_UPLOAD_BYTES", str(2 * 1024 * 1024 * 1024))
        with pytest.raises(ValidationError):
            Settings(_env_file=None)


class TestDatabaseUrlResolution:
    def test_relative_sqlite_path_becomes_absolute(self, settings: Settings) -> None:
        expected = (PROJECT_ROOT / "data" / "sentinelflow.db").resolve()
        assert settings.database_url == f"sqlite:///{expected}"

    def test_absolute_sqlite_path_is_untouched(self, clean_env: pytest.MonkeyPatch) -> None:
        url = "sqlite:////var/lib/sentinelflow/db.sqlite"
        clean_env.setenv("SENTINELFLOW_DATABASE_URL", url)
        assert Settings(_env_file=None).database_url == url

    def test_in_memory_database_is_untouched(self, clean_env: pytest.MonkeyPatch) -> None:
        clean_env.setenv("SENTINELFLOW_DATABASE_URL", "sqlite:///:memory:")
        assert Settings(_env_file=None).database_url == "sqlite:///:memory:"

    def test_relative_log_file_resolves_against_project_root(
        self, clean_env: pytest.MonkeyPatch
    ) -> None:
        clean_env.setenv("SENTINELFLOW_LOG_FILE", "logs/app.log")
        resolved = Settings(_env_file=None).log_file
        assert resolved == (PROJECT_ROOT / "logs" / "app.log").resolve()
        assert Path(resolved).is_absolute()


class TestSummary:
    def test_summary_is_json_safe_and_complete(self, settings: Settings) -> None:
        import json

        summary = settings.summary()
        json.dumps(summary)  # must not raise
        for key in ("environment", "ai_enabled", "ai_active", "database_url", "version"):
            assert key in summary

    def test_summary_is_an_allow_list(self, settings: Settings) -> None:
        """Only explicitly-listed keys are exposed, so future secrets cannot leak."""
        allowed = {
            "app_name",
            "version",
            "environment",
            "debug",
            "database_url",
            "api",
            "api_rate_limit_per_minute",
            "api_docs_enabled",
            "log_level",
            "log_format",
            "log_file",
            "ai_enabled",
            "ai_provider",
            "ai_active",
            "correlation_window_minutes",
            "max_upload_bytes",
            "max_events_per_import",
        }
        assert set(settings.summary()) == allowed


class TestSingleton:
    def test_get_settings_is_cached(self, clean_env: pytest.MonkeyPatch) -> None:
        assert get_settings() is get_settings()
        get_settings.cache_clear()
