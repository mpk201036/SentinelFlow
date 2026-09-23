"""Stage 1 — logging safety.

These tests encode two security requirements:
  * credentials must never reach a log sink;
  * untrusted event data must never be able to forge log lines.
"""

from __future__ import annotations

import io
import json
import logging

import pytest

from app.core.config import LogFormat, Settings
from app.core.logging import (
    REDACTED,
    JsonFormatter,
    SecretRedactingFilter,
    configure_logging,
    get_logger,
    redact_secrets,
    sanitize_for_log,
)

pytestmark = pytest.mark.unit


def _capturing_logger(name: str, formatter: logging.Formatter | None = None):
    """Build an isolated logger writing into a StringIO through our filter."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(formatter or logging.Formatter("%(message)s"))
    handler.addFilter(SecretRedactingFilter())
    logger = logging.getLogger(name)
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    return logger, stream


class TestSecretRedaction:
    @pytest.mark.parametrize(
        "text, secret",
        [
            ("user logged in with password=hunter2", "hunter2"),
            ('config {"api_key": "sk-live-abcdef123456"}', "sk-live-abcdef123456"),
            ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig", "eyJhbGciOiJIUzI1NiJ9"),
            ("token = 9f8a7b6c5d4e3f2a1b", "9f8a7b6c5d4e3f2a1b"),
            ("client_secret:s3cr3t-value", "s3cr3t-value"),
            ("connecting to https://svc:Pa55w0rd@internal.example/db", "Pa55w0rd"),
        ],
    )
    def test_credentials_are_removed(self, text: str, secret: str) -> None:
        result = redact_secrets(text)
        assert secret not in result
        assert REDACTED in result

    def test_non_sensitive_text_is_preserved(self) -> None:
        text = "process powershell.exe spawned by cmd.exe on WIN-LAB-01"
        assert redact_secrets(text) == text

    def test_redaction_applies_through_the_logging_filter(self) -> None:
        logger, stream = _capturing_logger("test.redaction")
        logger.info("auth attempt for %s with password=%s", "lab-user", "CorrectHorse1!")
        output = stream.getvalue()
        assert "CorrectHorse1!" not in output
        assert "lab-user" in output
        assert REDACTED in output

    def test_extra_fields_are_sanitised(self) -> None:
        logger, stream = _capturing_logger("test.extra")
        logger.info("event ingested", extra={"command_line": "cmd /c set TOKEN=abc123def456"})
        assert "abc123def456" not in stream.getvalue() or REDACTED in stream.getvalue()


class TestLogInjectionDefence:
    def test_newlines_cannot_forge_a_second_log_line(self) -> None:
        """A hostile command_line field must not be able to fabricate log entries."""
        hostile = "whoami\n2026-09-23T00:00:00 | CRITICAL | sentinelflow | HOST COMPROMISED"
        logger, stream = _capturing_logger("test.injection")
        logger.warning("suspicious process: %s", hostile)
        output = stream.getvalue()
        assert output.count("\n") == 1  # only the handler's own terminator
        assert "\\n" in output  # the injected newline was escaped, not dropped

    @pytest.mark.parametrize("control", ["\x00", "\x07", "\x1b[31m", "\x7f"])
    def test_control_characters_are_stripped(self, control: str) -> None:
        result = sanitize_for_log(f"payload{control}end")
        assert control.replace("[31m", "") not in result
        assert "payloadend" in result or "payload[31mend" in result

    def test_oversized_messages_are_truncated(self) -> None:
        result = sanitize_for_log("A" * 50_000, max_length=100)
        assert len(result) < 200
        assert "truncated" in result

    def test_non_string_values_are_accepted(self) -> None:
        assert sanitize_for_log(1234) == "1234"
        assert sanitize_for_log(None) == "None"


class TestJsonFormatter:
    def test_output_is_valid_json_with_expected_fields(self) -> None:
        logger, stream = _capturing_logger("test.json", JsonFormatter())
        logger.info("alert created", extra={"alert_id": "a-1", "rule_id": "SF-0001"})
        payload = json.loads(stream.getvalue().strip())
        assert payload["level"] == "INFO"
        assert payload["message"] == "alert created"
        assert payload["alert_id"] == "a-1"
        assert payload["rule_id"] == "SF-0001"
        assert payload["timestamp"].endswith("+00:00")

    def test_exceptions_are_captured(self) -> None:
        logger, stream = _capturing_logger("test.json.exc", JsonFormatter())
        try:
            raise ValueError("boom")
        except ValueError:
            logger.exception("pipeline failure")
        payload = json.loads(stream.getvalue().strip())
        assert "ValueError: boom" in payload["exception"]


class TestConfigureLogging:
    def test_installs_a_single_handler_and_is_idempotent(self, settings: Settings) -> None:
        configure_logging(settings)
        configure_logging(settings)
        root = logging.getLogger()
        ours = [h for h in root.handlers if getattr(h, "_sentinelflow", False)]
        assert len(ours) == 1
        assert root.level == logging.INFO

    def test_force_reconfiguration_replaces_handlers(self, settings: Settings) -> None:
        configure_logging(settings)
        configure_logging(Settings(_env_file=None, log_level="DEBUG"), force=True)
        root = logging.getLogger()
        ours = [h for h in root.handlers if getattr(h, "_sentinelflow", False)]
        assert len(ours) == 1
        assert root.level == logging.DEBUG

    def test_file_handler_is_created_with_parent_directories(self, tmp_path, clean_env) -> None:
        log_file = tmp_path / "nested" / "sentinelflow.log"
        configure_logging(Settings(_env_file=None, log_file=log_file), force=True)
        get_logger("test.file").error("disk pressure on %s", "WIN-LAB-01")
        for handler in logging.getLogger().handlers:
            handler.flush()
        assert log_file.exists()
        assert "WIN-LAB-01" in log_file.read_text(encoding="utf-8")

    def test_json_format_selected_from_settings(self, clean_env) -> None:
        configure_logging(Settings(_env_file=None, log_format=LogFormat.JSON), force=True)
        handler = next(
            h for h in logging.getLogger().handlers if getattr(h, "_sentinelflow", False)
        )
        assert isinstance(handler.formatter, JsonFormatter)


class TestGetLogger:
    def test_names_are_namespaced(self) -> None:
        assert get_logger("app.detection").name == "sentinelflow.app.detection"
        assert get_logger("sentinelflow.api").name == "sentinelflow.api"
