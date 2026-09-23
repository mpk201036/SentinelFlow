"""Enrichment: turning event fields into indicators and context.

patterns    regexes paired with the rejection rules that make them usable
defang      refanging hxxp:// and evil[.]example, on a copy only
extractor   structured fields first, free text second
service     storage: one indicator per (type, value), linked to every event
"""

from app.enrichment.defang import looks_defanged, refang
from app.enrichment.extractor import (
    MAX_INDICATORS_PER_EVENT,
    ExtractionResult,
    IOCExtractor,
    extract_indicators,
    indicator_event_ids,
    sighting_window,
)
from app.enrichment.patterns import VALID_TLDS, has_valid_tld
from app.enrichment.service import EnrichmentService, EnrichmentSummary

__all__ = [
    "MAX_INDICATORS_PER_EVENT",
    "VALID_TLDS",
    "EnrichmentService",
    "EnrichmentSummary",
    "ExtractionResult",
    "IOCExtractor",
    "extract_indicators",
    "has_valid_tld",
    "indicator_event_ids",
    "looks_defanged",
    "refang",
    "sighting_window",
]
