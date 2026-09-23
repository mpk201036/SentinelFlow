"""Adapter interface and shared helpers.

An adapter's entire job is translation: take one record in whatever shape a
source produces and return a :class:`~app.models.event.SecurityEvent`. It makes
no decisions about severity, runs no detection logic and stores nothing.

Adding a source means adding one adapter and its tests. Nothing downstream
changes, which is the payoff for having a canonical schema at all.

Two conventions keep adapters short and honest:

* **Field lookup is case-insensitive and accepts several spellings.** Real
  exports disagree about ``Computer`` vs ``computer`` vs ``hostname``, and an
  adapter that only handles one of them fails on the next export.
* **The original record is always preserved** in ``raw_event``. Normalisation
  is lossy by design; the analyst must still be able to see what arrived.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any, ClassVar

from app.models.event import SecurityEvent


class AdapterError(ValueError):
    """Raised when a record cannot be translated by this adapter."""


class RecordView:
    """Case-insensitive, multi-spelling read access to one source record."""

    def __init__(self, record: Mapping[str, Any]) -> None:
        self._data = {str(key).strip().lower(): value for key, value in record.items()}
        self.original = dict(record)

    def __contains__(self, name: str) -> bool:
        return name.lower() in self._data

    def get(self, *names: str, default: Any = None) -> Any:
        """First non-empty value among ``names``."""
        for name in names:
            value = self._data.get(name.lower())
            if value is None:
                continue
            if isinstance(value, str) and not value.strip():
                continue
            # Windows exports use "-" to mean "not applicable".
            if isinstance(value, str) and value.strip() == "-":
                continue
            return value
        return default

    def text(self, *names: str) -> str | None:
        value = self.get(*names)
        return None if value is None else str(value)

    def integer(self, *names: str) -> int | None:
        value = self.get(*names)
        if value is None:
            return None
        try:
            # Sysmon writes process ids in hex in some exports.
            text = str(value).strip()
            return int(text, 16) if text.lower().startswith("0x") else int(float(text))
        except (TypeError, ValueError):
            return None

    def is_empty(self) -> bool:
        return not any(
            value is not None and str(value).strip() not in ("", "-")
            for value in self._data.values()
        )


class SourceAdapter(ABC):
    """Translates one source's records into canonical events."""

    #: Value written to ``SecurityEvent.source``.
    name: ClassVar[str]
    #: Alternative names accepted on the command line and in API payloads.
    aliases: ClassVar[tuple[str, ...]] = ()
    #: Human-readable description, shown by ``sentinelflow adapters``.
    description: ClassVar[str] = ""

    @abstractmethod
    def normalise(self, record: Mapping[str, Any]) -> SecurityEvent:
        """Translate one record. Raise :class:`AdapterError` if impossible."""

    def matches(self, record: Mapping[str, Any]) -> bool:
        """Whether this adapter recognises the record's shape.

        Used only for auto-detection, which is a convenience. An explicit
        ``--source`` always wins, because guessing wrong is worse than asking.
        """
        return False

    def build(self, view: RecordView, **fields: Any) -> SecurityEvent:
        """Construct an event, dropping empty fields and keeping the original."""
        payload = {key: value for key, value in fields.items() if value not in (None, "")}
        payload.setdefault("source", self.name)
        payload["raw_event"] = view.original
        return SecurityEvent(**payload)


# ---------------------------------------------------------------------------
# Shared parsing helpers
# ---------------------------------------------------------------------------
_HASH_PAIR_RE = re.compile(r"(?P<algorithm>MD5|SHA1|SHA256|IMPHASH)\s*=\s*(?P<digest>[0-9a-fA-F]+)")


def image_basename(path: Any) -> str | None:
    """Process name from a full image path, on either path separator."""
    if path is None:
        return None
    text = str(path).strip().replace("\\", "/")
    name = text.rsplit("/", 1)[-1]
    return name or None


def preferred_hash(value: Any) -> str | None:
    """Pick the strongest digest from a Sysmon-style ``Hashes`` field.

    ``SHA256=...,MD5=...`` is normal; a bare digest is also accepted. SHA256 is
    preferred because a collision-prone digest is a poor correlation key.
    """
    if value is None:
        return None
    text = str(value).strip()
    pairs = {
        match.group("algorithm").upper(): match.group("digest")
        for match in _HASH_PAIR_RE.finditer(text)
    }
    for algorithm in ("SHA256", "SHA1", "MD5"):
        if algorithm in pairs:
            return pairs[algorithm]
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", text):
        return text
    return None


def first_ip(*values: Any) -> str | None:
    """First value that plausibly looks like an address, else ``None``.

    Windows writes ``-``, ``::1`` and occasionally a hostname into ``IpAddress``.
    Returning ``None`` for anything questionable is correct: the schema will
    reject a non-address, and losing the whole event over a junk field would be
    worse than losing the field.
    """
    for value in values:
        if value is None:
            continue
        text = str(value).strip().strip("[]")
        if not text or text == "-":
            continue
        if re.fullmatch(r"[0-9.]+|[0-9a-fA-F:.]+", text) and any(c in text for c in ".:"):
            return text
    return None
