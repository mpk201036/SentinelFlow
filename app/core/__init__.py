"""Cross-cutting concerns: configuration, logging and shared security helpers."""

from app.core.config import (
    PROJECT_ROOT,
    AIProvider,
    Environment,
    LogFormat,
    Settings,
    get_settings,
)
from app.core.logging import configure_logging, get_logger, redact_secrets, sanitize_for_log
from app.core.sanitize import clean_line, clean_text, normalize_slug

__all__ = [
    "PROJECT_ROOT",
    "AIProvider",
    "Environment",
    "LogFormat",
    "Settings",
    "clean_line",
    "clean_text",
    "configure_logging",
    "get_logger",
    "get_settings",
    "normalize_slug",
    "redact_secrets",
    "sanitize_for_log",
]
