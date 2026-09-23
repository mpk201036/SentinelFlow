"""Adapter registry.

Resolution order is explicit and deliberate. Auto-detection tries the specific
adapters first and falls back to the canonical one, because a record that looks
canonical is the least informative guess available. An explicit source name
always wins over detection: guessing wrong silently mislabels evidence, which is
worse than refusing to guess.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.core.logging import get_logger
from app.ingestion.adapters.base import AdapterError, RecordView, SourceAdapter
from app.ingestion.adapters.canonical import CanonicalAdapter
from app.ingestion.adapters.driftwatch import DriftWatchAdapter
from app.ingestion.adapters.firewall import FirewallAdapter
from app.ingestion.adapters.ghostcredential import GhostCredentialAdapter
from app.ingestion.adapters.sysmon import SysmonAdapter
from app.ingestion.adapters.windows_security import WindowsSecurityAdapter

logger = get_logger(__name__)


class UnknownAdapterError(ValueError):
    """Raised when a requested source name has no adapter."""


#: Most specific first; the canonical adapter is the fallback.
ADAPTERS: tuple[SourceAdapter, ...] = (
    GhostCredentialAdapter(),
    DriftWatchAdapter(),
    SysmonAdapter(),
    WindowsSecurityAdapter(),
    FirewallAdapter(),
    CanonicalAdapter(),
)

_BY_NAME: dict[str, SourceAdapter] = {}
for _adapter in ADAPTERS:
    _BY_NAME[_adapter.name] = _adapter
    for _alias in _adapter.aliases:
        _BY_NAME[_alias] = _adapter


def list_adapters() -> list[SourceAdapter]:
    """Every registered adapter, in resolution order."""
    return list(ADAPTERS)


def adapter_names() -> list[str]:
    return [adapter.name for adapter in ADAPTERS]


def get_adapter(name: str) -> SourceAdapter:
    """Look up an adapter by name or alias."""
    key = str(name).strip().lower().replace("-", "_")
    adapter = _BY_NAME.get(key)
    if adapter is None:
        raise UnknownAdapterError(
            f"unknown source {name!r}. Available: {', '.join(sorted(adapter_names()))}"
        )
    return adapter


def detect_adapter(record: Mapping[str, Any]) -> SourceAdapter | None:
    """Best-guess adapter for a record, or ``None`` if nothing recognises it."""
    for adapter in ADAPTERS:
        try:
            if adapter.matches(record):
                return adapter
        except Exception as exc:
            # A broken matcher must not break detection for every other source,
            # but it must not disappear either.
            logger.debug("adapter %s failed to match a record: %s", adapter.name, exc)
            continue
    return None


def resolve_adapter(
    *, name: str | None = None, sample: Mapping[str, Any] | None = None
) -> SourceAdapter:
    """Pick an adapter: an explicit name wins, otherwise detect from a sample."""
    if name:
        return get_adapter(name)
    if sample is not None:
        detected = detect_adapter(sample)
        if detected is not None:
            return detected
    raise UnknownAdapterError(
        "could not determine the source format. Pass an explicit source name; "
        f"available: {', '.join(sorted(adapter_names()))}"
    )


__all__ = [
    "ADAPTERS",
    "AdapterError",
    "CanonicalAdapter",
    "DriftWatchAdapter",
    "FirewallAdapter",
    "GhostCredentialAdapter",
    "RecordView",
    "SourceAdapter",
    "SysmonAdapter",
    "UnknownAdapterError",
    "WindowsSecurityAdapter",
    "adapter_names",
    "detect_adapter",
    "get_adapter",
    "list_adapters",
    "resolve_adapter",
]
