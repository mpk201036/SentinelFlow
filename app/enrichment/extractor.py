"""Indicator extraction.

An indicator is **a fact about a string that appeared in an event**. Nothing
more. ``8.8.8.8`` in a DNS query is an indicator; it is not malicious, and this
module records no opinion about it. Deciding what an indicator means is the
detection engine's job, and deciding what to do about it is the analyst's.

Extraction runs in two passes, and the order matters:

1. **Structured fields first.** ``src_ip`` is an IP address because the schema
   validated it as one. Re-deriving that with a regex would be slower and less
   reliable, and it would lose the field name — which is the context that makes
   an indicator readable ("seen in ``dst_ip``" says more than "seen").

2. **Free text second.** ``command_line`` and ``event_message`` are where the
   interesting indicators hide: a URL passed to a downloader, an address in an
   error message, a hash in a log line. This pass is where false positives come
   from, so the patterns in :mod:`app.enrichment.patterns` are paired with
   rejection rules rather than used alone.

Sightings are timestamped with the **event's** time, not the time extraction
ran. An indicator first seen in a log from three days ago was first seen three
days ago.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlsplit
from uuid import UUID

from app.core.logging import get_logger
from app.enrichment.defang import refang
from app.enrichment.patterns import (
    DOMAIN_RE,
    EMAIL_RE,
    IPV4_RE,
    IPV6_RE,
    MD5_RE,
    POSIX_PATH_RE,
    PROCESS_NAME_RE,
    SHA1_RE,
    SHA256_RE,
    URL_RE,
    WINDOWS_PATH_RE,
    has_valid_tld,
)
from app.models.enums import IndicatorType
from app.models.event import SecurityEvent
from app.models.indicator import Indicator

logger = get_logger(__name__)

#: Upper bound per event. A crafted command line should cost one noisy alert,
#: not ten thousand rows.
MAX_INDICATORS_PER_EVENT = 200

#: Free-text fields are already length-capped by the schema; this is a second
#: bound in case that ever changes.
MAX_SCAN_CHARS = 16_384

#: Hash length to indicator type.
_HASH_TYPES = {32: IndicatorType.MD5, 40: IndicatorType.SHA1, 64: IndicatorType.SHA256}

#: Free-text fields worth scanning, in the order they are reported.
FREE_TEXT_FIELDS = ("command_line", "event_message", "file_path", "url")


@dataclass
class ExtractionResult:
    """Indicators found in one event."""

    indicators: list[Indicator] = field(default_factory=list)
    scanned_fields: tuple[str, ...] = ()
    truncated: bool = False

    def __len__(self) -> int:
        return len(self.indicators)

    def by_type(self) -> dict[IndicatorType, list[Indicator]]:
        grouped: dict[IndicatorType, list[Indicator]] = {}
        for indicator in self.indicators:
            grouped.setdefault(indicator.indicator_type, []).append(indicator)
        return grouped

    def values_of(self, indicator_type: IndicatorType) -> list[str]:
        return [i.value for i in self.indicators if i.indicator_type is indicator_type]

    def counts(self) -> dict[str, int]:
        return {key.value: len(values) for key, values in sorted(self.by_type().items())}


class IOCExtractor:
    """Pulls indicators out of a normalised event."""

    def __init__(
        self,
        *,
        max_indicators: int = MAX_INDICATORS_PER_EVENT,
        scan_free_text: bool = True,
        include_internal: bool = True,
    ) -> None:
        self.max_indicators = max_indicators
        self.scan_free_text = scan_free_text
        #: Internal addresses are kept by default. They are not threat
        #: intelligence, but "which internal host" is most of triage.
        self.include_internal = include_internal

    # ------------------------------------------------------------------
    def extract(self, event: SecurityEvent) -> ExtractionResult:
        """Extract every indicator present in ``event``."""
        collected: dict[tuple[IndicatorType, str], Indicator] = {}
        scanned: list[str] = []
        truncated = False

        for indicator_type, value, source_field in self._structured(event):
            scanned.append(source_field)
            if not self._record(collected, indicator_type, value, source_field, event):
                truncated = True
                break

        if self.scan_free_text and not truncated:
            for source_field in FREE_TEXT_FIELDS:
                text = getattr(event, source_field, None)
                if not text:
                    continue
                scanned.append(source_field)
                for indicator_type, value in self._scan_text(str(text)):
                    if not self._record(collected, indicator_type, value, source_field, event):
                        truncated = True
                        break
                if truncated:
                    break

        if truncated:
            logger.warning(
                "indicator limit of %s reached for event %s", self.max_indicators, event.event_id
            )

        return ExtractionResult(
            indicators=list(collected.values()),
            scanned_fields=tuple(dict.fromkeys(scanned)),
            truncated=truncated,
        )

    # ------------------------------------------------------------------
    # Pass 1: structured fields
    # ------------------------------------------------------------------
    def _structured(self, event: SecurityEvent) -> list[tuple[IndicatorType, str, str]]:
        """Indicators the schema already guarantees, with their field names."""
        found: list[tuple[IndicatorType, str, str]] = []

        for source_field in ("src_ip", "dst_ip"):
            value = getattr(event, source_field)
            if value:
                found.append((_ip_type(value), value, source_field))

        if event.domain:
            found.append((IndicatorType.DOMAIN, event.domain, "domain"))

        if event.url:
            found.append((IndicatorType.URL, event.url, "url"))
            host = _url_host(event.url)
            if host is not None:
                found.append((host[0], host[1], "url"))

        if event.file_hash:
            hash_type = _HASH_TYPES.get(len(event.file_hash))
            if hash_type is not None:
                found.append((hash_type, event.file_hash, "file_hash"))

        if event.file_path:
            found.append((IndicatorType.FILE_PATH, event.file_path, "file_path"))

        for source_field in ("process_name", "parent_process"):
            value = getattr(event, source_field)
            if value:
                found.append((IndicatorType.PROCESS_NAME, value, source_field))

        return found

    # ------------------------------------------------------------------
    # Pass 2: free text
    # ------------------------------------------------------------------
    def _scan_text(self, text: str) -> list[tuple[IndicatorType, str]]:
        """Find indicators in free text, refanging a copy of it first."""
        scannable = refang(text[:MAX_SCAN_CHARS])
        found: list[tuple[IndicatorType, str]] = []

        for match in URL_RE.findall(scannable):
            url = match.rstrip(".,;:!?'\"")
            found.append((IndicatorType.URL, url))
            host = _url_host(url)
            if host is not None:
                found.append(host)

        for match in EMAIL_RE.findall(scannable):
            if has_valid_tld(match):
                found.append((IndicatorType.EMAIL, match))

        for match in IPV4_RE.findall(scannable):
            if _is_ip(match):
                found.append((IndicatorType.IPV4, match))

        for match in IPV6_RE.findall(scannable):
            # The pattern is permissive on purpose; ipaddress is the real test,
            # and it rejects the timestamps and MAC addresses it also matches.
            if _is_ip(match):
                found.append((IndicatorType.IPV6, match))

        for pattern, indicator_type in (
            (SHA256_RE, IndicatorType.SHA256),
            (SHA1_RE, IndicatorType.SHA1),
            (MD5_RE, IndicatorType.MD5),
        ):
            found.extend((indicator_type, match) for match in pattern.findall(scannable))

        for match in DOMAIN_RE.findall(scannable):
            if has_valid_tld(match) and not _is_ip(match):
                found.append((IndicatorType.DOMAIN, match))

        for pattern in (WINDOWS_PATH_RE, POSIX_PATH_RE):
            found.extend(
                (IndicatorType.FILE_PATH, match.rstrip(".,;:"))
                for match in pattern.findall(scannable)
            )

        found.extend(
            (IndicatorType.PROCESS_NAME, match) for match in PROCESS_NAME_RE.findall(scannable)
        )
        return found

    # ------------------------------------------------------------------
    def _record(
        self,
        collected: dict[tuple[IndicatorType, str], Indicator],
        indicator_type: IndicatorType,
        value: str,
        source_field: str,
        event: SecurityEvent,
    ) -> bool:
        """Add or merge one indicator. Returns False once the cap is reached."""
        try:
            indicator = Indicator(
                indicator_type=indicator_type,
                value=value,
                source_event_id=event.event_id,
                source_field=source_field,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
            )
        except ValueError:
            # The value did not survive its type's own normalisation. That is a
            # rejected candidate, not an error worth failing the event over.
            return True

        key = (indicator.indicator_type, indicator.value)
        existing = collected.get(key)
        if existing is not None:
            collected[key] = existing.model_copy(update={"occurrences": existing.occurrences + 1})
            return True

        if not self.include_internal and indicator.is_internal:
            return True
        if len(collected) >= self.max_indicators:
            return False

        collected[key] = indicator
        return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _ip_type(value: str) -> IndicatorType:
    return (
        IndicatorType.IPV6
        if isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
        else IndicatorType.IPV4
    )


def _url_host(url: str) -> tuple[IndicatorType, str] | None:
    """The host of a URL, as a domain or address indicator.

    A URL is only half an indicator: the host is what correlates against a DNS
    query or a network connection seen elsewhere.
    """
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.strip("[]")
    if _is_ip(host):
        return (_ip_type(host), host)
    if "." in host and has_valid_tld(host):
        return (IndicatorType.DOMAIN, host)
    return None


def extract_indicators(event: SecurityEvent) -> list[Indicator]:
    """Convenience wrapper for the default extractor."""
    return IOCExtractor().extract(event).indicators


def sighting_window(indicators: list[Indicator]) -> tuple[datetime | None, datetime | None]:
    """Earliest and latest sighting across a set of indicators."""
    if not indicators:
        return (None, None)
    return (
        min(indicator.first_seen for indicator in indicators),
        max(indicator.last_seen for indicator in indicators),
    )


def indicator_event_ids(indicators: list[Indicator]) -> list[UUID]:
    """Distinct source events represented in a set of indicators."""
    seen: dict[UUID, None] = {}
    for indicator in indicators:
        if indicator.source_event_id is not None:
            seen.setdefault(indicator.source_event_id, None)
    return list(seen)
