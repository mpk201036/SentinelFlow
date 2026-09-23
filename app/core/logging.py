"""Application logging with secret redaction and log-injection defence.

SentinelFlow logs data that originates from untrusted sources: command lines,
usernames, file paths and URLs taken from imported security events. Two
concrete risks follow from that, and this module addresses both.

1. **Secret leakage.** Event data or configuration may contain credentials.
   ``SecretRedactingFilter`` rewrites anything that looks like a password,
   token, API key or bearer credential before it reaches a handler.

2. **Log injection / forging.** An attacker who controls a field can embed
   newlines and fabricate convincing log lines, or embed ANSI escapes to
   manipulate an analyst's terminal. ``sanitize_for_log`` escapes newlines and
   strips control characters, so one event can only ever produce one log line.

Redaction happens in a ``logging.Filter`` attached to the *handlers*, so it
applies to every log record regardless of which module emitted it.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.config import LogFormat, Settings, get_settings

REDACTED = "[REDACTED]"

#: Maximum characters kept from a single log message. Untrusted command lines
#: can be enormous; truncating bounds log growth and terminal flooding.
MAX_LOG_MESSAGE_LENGTH = 4_000

#: Field names whose values must never appear in logs.
_SENSITIVE_KEY_PATTERN = (
    r"password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|apikey|"
    r"access[_-]?token|refresh[_-]?token|id[_-]?token|token|authorization|"
    r"auth[_-]?header|private[_-]?key|session[_-]?id|cookie|credential|passphrase"
)

# The key may be quoted, as in JSON: {"api_key": "..."}
_KEY_VALUE_RE = re.compile(
    rf"(?P<key>[\"']?\b(?:{_SENSITIVE_KEY_PATTERN})\b[\"']?)"
    r"(?P<sep>\s*[:=]\s*)"
    r"(?P<quote>[\"']?)"
    r"(?P<value>[^\s\"',;}\)\]]+)"
    r"(?P=quote)",
    re.IGNORECASE,
)

_BEARER_RE = re.compile(r"\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)

#: Credentials embedded in a URL, e.g. https://user:pass@host/path
_URL_CREDENTIALS_RE = re.compile(r"(?P<scheme>\b[a-z][a-z0-9+.-]*://)(?P<user>[^\s:/@]+):[^\s@]+@")

#: Control characters that have no business in a log line. Tab is preserved.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

#: Standard LogRecord attributes; anything else was supplied via ``extra=``.
_RESERVED_RECORD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", None, None).__dict__) | {
    "message",
    "asctime",
    "taskName",
}

_configured = False


# ---------------------------------------------------------------------------
# Sanitisation helpers
# ---------------------------------------------------------------------------
def redact_secrets(text: str) -> str:
    """Replace credential-looking values in ``text`` with ``[REDACTED]``."""
    # Order matters: `Authorization: Bearer <jwt>` must be handled by the bearer
    # rule first, otherwise the key/value rule consumes the word "Bearer" as the
    # value and leaves the actual token in the log line.
    text = _BEARER_RE.sub(rf"\g<1> {REDACTED}", text)
    text = _URL_CREDENTIALS_RE.sub(rf"\g<scheme>\g<user>:{REDACTED}@", text)
    text = _KEY_VALUE_RE.sub(rf"\g<key>\g<sep>\g<quote>{REDACTED}\g<quote>", text)
    return text


def sanitize_for_log(value: Any, max_length: int = MAX_LOG_MESSAGE_LENGTH) -> str:
    """Make an arbitrary, possibly hostile value safe to write to a log.

    Escapes newlines (so injected content cannot forge additional log lines),
    removes control/ANSI characters, redacts secrets and truncates.
    """
    text = value if isinstance(value, str) else str(value)
    text = text.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n")
    text = _CONTROL_CHARS_RE.sub("", text)
    text = redact_secrets(text)
    if len(text) > max_length:
        text = f"{text[:max_length]}...[truncated {len(text) - max_length} chars]"
    return text


class SecretRedactingFilter(logging.Filter):
    """Sanitise every log record before a handler formats it.

    The already-interpolated message replaces ``record.msg`` and ``record.args``
    is cleared, which guarantees that arguments cannot re-introduce unsanitised
    content during formatting.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - defensive: bad %-format args
            message = str(record.msg)
        record.msg = sanitize_for_log(message)
        record.args = ()

        for key, value in list(record.__dict__.items()):
            if key not in _RESERVED_RECORD_ATTRS and isinstance(value, str):
                record.__dict__[key] = sanitize_for_log(value, max_length=1_000)
        return True


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------
class JsonFormatter(logging.Formatter):
    """Emit one JSON object per log record, suitable for ingestion by a SIEM."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED_RECORD_ATTRS:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


_TEXT_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-28s | %(message)s"


def _build_formatter(log_format: LogFormat) -> logging.Formatter:
    if log_format is LogFormat.JSON:
        return JsonFormatter()
    return logging.Formatter(_TEXT_FORMAT, datefmt="%Y-%m-%dT%H:%M:%S%z")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
def configure_logging(settings: Settings | None = None, *, force: bool = False) -> None:
    """Configure root logging for the application.

    Idempotent: calling it repeatedly has no additional effect unless
    ``force=True``. Handlers installed by SentinelFlow are tagged so that
    reconfiguration never removes handlers owned by a host application.
    """
    global _configured
    if _configured and not force:
        return

    settings = settings or get_settings()
    root = logging.getLogger()

    for handler in list(root.handlers):
        if getattr(handler, "_sentinelflow", False):
            root.removeHandler(handler)
            handler.close()

    formatter = _build_formatter(settings.log_format)
    redaction_filter = SecretRedactingFilter()

    stream_handler: logging.Handler = logging.StreamHandler(stream=sys.stderr)
    stream_handler.setFormatter(formatter)
    stream_handler.addFilter(redaction_filter)
    stream_handler._sentinelflow = True  # type: ignore[attr-defined]
    root.addHandler(stream_handler)

    if settings.log_file is not None:
        log_path = Path(settings.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        file_handler.addFilter(redaction_filter)
        file_handler._sentinelflow = True  # type: ignore[attr-defined]
        root.addHandler(file_handler)

    root.setLevel(settings.log_level)

    # Third-party loggers are noisy at DEBUG and rarely useful here.
    for noisy in ("httpx", "httpcore", "multipart", "watchfiles"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced application logger."""
    return logging.getLogger(name if name.startswith("sentinelflow") else f"sentinelflow.{name}")


def reset_logging() -> None:
    """Remove SentinelFlow handlers. Intended for tests."""
    global _configured
    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, "_sentinelflow", False):
            root.removeHandler(handler)
            handler.close()
    _configured = False
