"""Parsing JSON and CSV into raw records.

Parsers do not validate, normalise or store. They turn bytes into a stream of
dictionaries, and — importantly — they turn *failures* into stream entries too.
One malformed line in a 5,000-line NDJSON export costs one event, not the whole
import.

Input here is untrusted by definition, so three limits are enforced before any
record is produced:

* **Record count**, so a file cannot queue unbounded work.
* **Nesting depth.** Deeply nested JSON is a denial-of-service primitive: the
  standard library parser recurses, and roughly a thousand opening brackets is
  enough to exhaust the C stack. The depth is checked, and ``RecursionError`` is
  caught as a last line of defence rather than propagating as a 500.
* **Field size**, via the caller's byte limit, applied before reading.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from app.models.ingestion import RejectionReason

#: Nesting beyond this is rejected. Real security events are flat; anything
#: this deep is either broken or hostile.
MAX_JSON_DEPTH = 32

#: Longest single CSV field. The default limit is 128 KiB and can be exhausted
#: by a crafted quoted field.
MAX_CSV_FIELD_BYTES = 256 * 1024

#: Delimiters the sniffer is allowed to choose between.
CSV_DELIMITERS = ",;\t|"


@dataclass
class ParsedRecord:
    """One entry from a parsed file: either a record or a reason it is not."""

    index: int
    record: dict[str, Any] | None = None
    reason: RejectionReason | None = None
    detail: str | None = None
    raw: str | None = None

    @property
    def ok(self) -> bool:
        return self.record is not None


def _decode(data: str | bytes) -> str:
    """Decode to text, tolerating a UTF-8 BOM and invalid bytes.

    ``errors="replace"`` rather than strict: a single bad byte in an export
    should cost the analyst one mangled character, not the whole file.
    """
    if isinstance(data, bytes):
        text = data.decode("utf-8-sig", errors="replace")
    else:
        text = data.lstrip("﻿")
    return text


def exceeds_depth(value: Any, max_depth: int = MAX_JSON_DEPTH) -> bool:
    """Whether a decoded structure nests deeper than ``max_depth``.

    Iterative, so checking the guard cannot itself blow the stack.
    """
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            return True
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
    return False


def _truncate(text: str, limit: int = 2_048) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


def parse_json_records(data: str | bytes, *, max_records: int = 10_000) -> Iterator[ParsedRecord]:
    """Parse a JSON array, a single object, or newline-delimited JSON.

    The format is detected rather than configured, because every export tool
    picks a different one and asking the analyst to know which is unhelpful.
    """
    text = _decode(data).strip()
    if not text:
        yield ParsedRecord(index=0, reason=RejectionReason.EMPTY_RECORD, detail="file is empty")
        return

    document: Any = None
    whole_document_error: str | None = None
    try:
        document = json.loads(text)
    except RecursionError:
        yield ParsedRecord(
            index=0,
            reason=RejectionReason.NESTING_TOO_DEEP,
            detail="JSON nesting exhausted the parser",
            raw=_truncate(text),
        )
        return
    except json.JSONDecodeError as exc:
        whole_document_error = str(exc)

    if whole_document_error is None:
        yield from _yield_document(document, max_records=max_records, raw=text)
        return

    # Not a single JSON document: try newline-delimited JSON, which is what
    # most log shippers emit.
    lines = [line for line in text.splitlines() if line.strip()]
    looks_like_ndjson = len(lines) > 1 and lines[0].lstrip().startswith(("{", "["))
    if not looks_like_ndjson:
        yield ParsedRecord(
            index=0,
            reason=RejectionReason.MALFORMED_JSON,
            detail=f"not valid JSON: {whole_document_error}",
            raw=_truncate(text),
        )
        return

    for index, line in enumerate(lines):
        if index >= max_records:
            yield _limit_record(index, max_records)
            return
        try:
            value = json.loads(line)
        except RecursionError:
            yield ParsedRecord(
                index=index,
                reason=RejectionReason.NESTING_TOO_DEEP,
                detail="JSON nesting exhausted the parser",
                raw=_truncate(line),
            )
            continue
        except json.JSONDecodeError as exc:
            yield ParsedRecord(
                index=index,
                reason=RejectionReason.MALFORMED_JSON,
                detail=f"line {index + 1}: {exc}",
                raw=_truncate(line),
            )
            continue
        yield _classify(index, value, raw=line)


def _yield_document(document: Any, *, max_records: int, raw: str) -> Iterator[ParsedRecord]:
    """Yield records from an already-decoded JSON document."""
    if isinstance(document, dict):
        # A wrapper such as {"events": [...]} is common enough to handle.
        for key in ("events", "records", "data", "results", "items"):
            inner = document.get(key)
            if isinstance(inner, list):
                yield from _yield_list(inner, max_records=max_records)
                return
        yield _classify(0, document, raw=raw)
        return

    if isinstance(document, list):
        yield from _yield_list(document, max_records=max_records)
        return

    yield ParsedRecord(
        index=0,
        reason=RejectionReason.NOT_AN_OBJECT,
        detail=f"expected an object or array, got {type(document).__name__}",
        raw=_truncate(raw),
    )


def _yield_list(items: list[Any], *, max_records: int) -> Iterator[ParsedRecord]:
    for index, item in enumerate(items):
        if index >= max_records:
            yield _limit_record(index, max_records)
            return
        yield _classify(index, item)


def _classify(index: int, value: Any, raw: str | None = None) -> ParsedRecord:
    """Turn one decoded value into a record or a typed rejection."""
    if not isinstance(value, dict):
        return ParsedRecord(
            index=index,
            reason=RejectionReason.NOT_AN_OBJECT,
            detail=f"expected an object, got {type(value).__name__}",
            raw=_truncate(raw or json.dumps(value, default=str)),
        )
    if exceeds_depth(value):
        return ParsedRecord(
            index=index,
            reason=RejectionReason.NESTING_TOO_DEEP,
            detail=f"nesting exceeds the limit of {MAX_JSON_DEPTH}",
            raw=_truncate(raw or "<nested object>"),
        )
    if not value:
        return ParsedRecord(
            index=index, reason=RejectionReason.EMPTY_RECORD, detail="record has no fields"
        )
    return ParsedRecord(index=index, record=value)


def _limit_record(index: int, max_records: int) -> ParsedRecord:
    return ParsedRecord(
        index=index,
        reason=RejectionReason.LIMIT_EXCEEDED,
        detail=f"stopped at the import limit of {max_records:,} records",
    )


def parse_csv_records(data: str | bytes, *, max_records: int = 10_000) -> Iterator[ParsedRecord]:
    """Parse CSV with a header row, detecting the delimiter."""
    text = _decode(data)
    if not text.strip():
        yield ParsedRecord(index=0, reason=RejectionReason.EMPTY_RECORD, detail="file is empty")
        return

    previous_limit = csv.field_size_limit()
    csv.field_size_limit(MAX_CSV_FIELD_BYTES)
    try:
        delimiter = _sniff_delimiter(text)
        reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
        if not reader.fieldnames:
            yield ParsedRecord(
                index=0, reason=RejectionReason.MALFORMED_CSV, detail="no header row found"
            )
            return

        for index, row in enumerate(reader):
            if index >= max_records:
                yield _limit_record(index, max_records)
                return
            yield _csv_row(index, row)
    except csv.Error as exc:
        yield ParsedRecord(
            index=0, reason=RejectionReason.MALFORMED_CSV, detail=f"CSV parse error: {exc}"
        )
    finally:
        csv.field_size_limit(previous_limit)


def _csv_row(index: int, row: dict[str | Any, Any]) -> ParsedRecord:
    """Clean one CSV row: drop empties, flag ragged rows."""
    if None in row:
        # DictReader puts surplus columns under the None key.
        return ParsedRecord(
            index=index,
            reason=RejectionReason.MALFORMED_CSV,
            detail=f"row {index + 1} has more fields than the header",
            raw=_truncate(str(row)),
        )
    cleaned = {
        str(key).strip(): value
        for key, value in row.items()
        if key is not None and value not in (None, "")
    }
    if not cleaned:
        return ParsedRecord(
            index=index, reason=RejectionReason.EMPTY_RECORD, detail=f"row {index + 1} is blank"
        )
    return ParsedRecord(index=index, record=cleaned)


def _sniff_delimiter(text: str) -> str:
    """Detect the delimiter, defaulting to a comma.

    Semicolon-delimited exports are common wherever the comma is a decimal
    separator, and failing on them would be an avoidable annoyance.
    """
    sample = text[:8_192]
    try:
        return csv.Sniffer().sniff(sample, delimiters=CSV_DELIMITERS).delimiter
    except csv.Error:
        return ","
