"""Ingestion orchestration: parse, normalise, validate, store, report.

The contract this service keeps is simple and load-bearing: **an import never
silently loses a record**. Every input either becomes a stored event or becomes
a stored rejection with a reason. The counts always add up, so an analyst can
tell the difference between "nothing happened on that host" and "the import
dropped 400 lines".

Re-importing identical content is a no-op, tracked by a hash of the file. Note
what is deliberately *not* deduplicated: individual events. Two identical failed
logons a second apart are two failures, and collapsing them would quietly break
every rule that counts repetitions — which is most of the interesting ones.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.display import counted
from app.core.logging import get_logger
from app.core.paths import check_file_size, resolve_within
from app.database import repository
from app.ingestion.adapters import AdapterError, SourceAdapter, UnknownAdapterError, resolve_adapter
from app.ingestion.parsers import ParsedRecord, parse_csv_records, parse_json_records
from app.models.analyst import AuditEntry
from app.models.enums import Actor, AuditAction
from app.models.event import SecurityEvent
from app.models.ingestion import IngestionReport, RejectedRecord, RejectionReason

logger = get_logger(__name__)

JSON_SUFFIXES = {".json", ".ndjson", ".jsonl"}
CSV_SUFFIXES = {".csv", ".tsv"}


@dataclass
class IngestionOutcome:
    """What an import produced: a serialisable report plus the events."""

    report: IngestionReport
    events: list[SecurityEvent] = field(default_factory=list)

    @property
    def accepted(self) -> int:
        return self.report.accepted

    @property
    def rejected(self) -> int:
        return self.report.rejected


class IngestionService:
    """Turns raw input into stored events."""

    def __init__(self, session: Session, settings: Settings | None = None) -> None:
        self.session = session
        self.settings = settings or get_settings()

    # ------------------------------------------------------------------
    # Entry points
    # ------------------------------------------------------------------
    def ingest_file(
        self,
        path: str | Path,
        *,
        adapter_name: str | None = None,
        allowed_roots: Iterable[str | Path] | None = None,
        force: bool = False,
        persist: bool = True,
    ) -> IngestionOutcome:
        """Import a JSON or CSV file from disk.

        ``allowed_roots`` confines the path to an allow-list, resolving symlinks
        first. Pass it whenever the path crossed a trust boundary. The CLI does
        not, because there the path comes from the operator, who already has a
        shell - and no network-reachable endpoint takes a path at all: the API
        receives file *contents* and uses the filename only to pick a parser.
        """
        candidate = Path(path)
        if allowed_roots is not None:
            candidate = resolve_within(candidate, allowed_roots)
        else:
            candidate = candidate.expanduser().resolve(strict=False)
            if not candidate.exists():
                raise FileNotFoundError(f"no such file: {candidate}")

        check_file_size(candidate, self.settings.max_upload_bytes)
        data = candidate.read_bytes()
        suffix = candidate.suffix.lower()

        if suffix in CSV_SUFFIXES:
            return self.ingest_csv(
                data, adapter_name=adapter_name, origin=candidate.name, force=force, persist=persist
            )
        if suffix in JSON_SUFFIXES:
            return self.ingest_json(
                data, adapter_name=adapter_name, origin=candidate.name, force=force, persist=persist
            )
        raise ValueError(
            f"unsupported file type {suffix!r}. Supported: "
            + ", ".join(sorted(JSON_SUFFIXES | CSV_SUFFIXES))
        )

    def ingest_json(
        self,
        data: str | bytes,
        *,
        adapter_name: str | None = None,
        origin: str = "json",
        force: bool = False,
        persist: bool = True,
    ) -> IngestionOutcome:
        records = parse_json_records(data, max_records=self.settings.max_events_per_import)
        return self._ingest(
            records,
            adapter_name=adapter_name,
            origin=origin,
            content_hash=_hash(data),
            force=force,
            persist=persist,
        )

    def ingest_csv(
        self,
        data: str | bytes,
        *,
        adapter_name: str | None = None,
        origin: str = "csv",
        force: bool = False,
        persist: bool = True,
    ) -> IngestionOutcome:
        records = parse_csv_records(data, max_records=self.settings.max_events_per_import)
        return self._ingest(
            records,
            adapter_name=adapter_name,
            origin=origin,
            content_hash=_hash(data),
            force=force,
            persist=persist,
        )

    def ingest_mappings(
        self,
        records: Iterable[Mapping[str, Any]],
        *,
        adapter_name: str | None = None,
        origin: str = "api",
        force: bool = False,
        persist: bool = True,
    ) -> IngestionOutcome:
        """Import already-decoded records, as the REST API and generator do.

        Idempotent by content unless ``force`` is set. A batch byte-identical to
        one already accepted - same records, same timestamps - is almost always
        a retry by a sender that did not see the first response, and treating
        it as new would double every event in it: a flaky network turned into a
        false brute-force alert. ``force`` exists for sources whose timestamps
        are too coarse to tell a genuine repeat from a retry.

        ``max_events_per_import`` applies here exactly as it does to files: the
        records beyond it are refused with a stated reason, not silently kept.
        """
        limit = self.settings.max_events_per_import
        parsed: list[ParsedRecord] = []
        for index, record in enumerate(records):
            if index >= limit:
                parsed.append(
                    ParsedRecord(
                        index=index,
                        reason=RejectionReason.LIMIT_EXCEEDED,
                        detail=f"stopped at the import limit of {limit:,} records",
                    )
                )
                break
            parsed.append(ParsedRecord(index=index, record=dict(record)))

        payload = json.dumps([p.record for p in parsed], default=str, sort_keys=True)
        return self._ingest(
            parsed,
            adapter_name=adapter_name,
            origin=origin,
            content_hash=_hash(payload),
            force=force,
            persist=persist,
        )

    # ------------------------------------------------------------------
    # Core
    # ------------------------------------------------------------------
    def _ingest(
        self,
        records: Iterable[ParsedRecord],
        *,
        adapter_name: str | None,
        origin: str,
        content_hash: str,
        force: bool,
        persist: bool,
    ) -> IngestionOutcome:
        report = IngestionReport(
            origin=origin, adapter=adapter_name or "auto", content_hash=content_hash
        )

        if persist and not force:
            existing = repository.find_batch_by_hash(self.session, content_hash)
            if existing is not None:
                logger.info(
                    "skipping %s: identical content imported at %s", origin, existing.imported_at
                )
                report.duplicate_batch = True
                report.batch_id = existing.batch_id
                report.accepted = existing.accepted
                report.rejected = existing.rejected
                report.finished_at = report.started_at
                return IngestionOutcome(report=report, events=[])

        materialised = list(records)
        adapter = self._choose_adapter(adapter_name, materialised, report, origin)
        if adapter is None:
            report.finished_at = _utcnow()
            return IngestionOutcome(report=report, events=[])

        report.adapter = adapter.name
        events: list[SecurityEvent] = []

        for parsed in materialised:
            if not parsed.ok:
                report.rejections.append(
                    RejectedRecord(
                        index=parsed.index,
                        reason=parsed.reason or RejectionReason.MALFORMED_JSON,
                        detail=parsed.detail or "record could not be parsed",
                        payload=parsed.raw,
                        origin=origin,
                        adapter=adapter.name,
                    )
                )
                continue

            if parsed.record is None:  # an unparsed record was handled just above
                raise RuntimeError("parser reported success without a record")
            try:
                events.append(adapter.normalise(parsed.record))
            except AdapterError as exc:
                report.rejections.append(
                    self._rejection(
                        parsed, RejectionReason.ADAPTER_ERROR, str(exc), origin, adapter
                    )
                )
            except ValidationError as exc:
                report.rejections.append(
                    self._rejection(
                        parsed, RejectionReason.SCHEMA_VALIDATION, _summarise(exc), origin, adapter
                    )
                )
            except ValueError as exc:
                # A normaliser rejecting a malformed IP, hash or URL. One bad
                # field costs one event, never the batch.
                report.rejections.append(
                    self._rejection(
                        parsed, RejectionReason.SCHEMA_VALIDATION, str(exc), origin, adapter
                    )
                )

        report.accepted = len(events)
        report.rejected = len(report.rejections)
        report.event_ids = [event.event_id for event in events]
        report.finished_at = _utcnow()

        if persist:
            self._persist(events, report)

        logger.info("ingested %s", report.summary())
        return IngestionOutcome(report=report, events=events)

    def _choose_adapter(
        self,
        adapter_name: str | None,
        records: list[ParsedRecord],
        report: IngestionReport,
        origin: str,
    ) -> SourceAdapter | None:
        """Resolve the adapter, recording a rejection if none can be chosen."""
        sample = next((parsed.record for parsed in records if parsed.ok), None)
        try:
            return resolve_adapter(name=adapter_name, sample=sample)
        except UnknownAdapterError as exc:
            report.rejections.append(
                RejectedRecord(
                    index=0,
                    reason=RejectionReason.UNKNOWN_SOURCE,
                    detail=str(exc),
                    origin=origin,
                )
            )
            report.rejected = len(report.rejections)
            return None

    def _rejection(
        self,
        parsed: ParsedRecord,
        reason: RejectionReason,
        detail: str,
        origin: str,
        adapter: SourceAdapter,
    ) -> RejectedRecord:
        return RejectedRecord(
            index=parsed.index,
            reason=reason,
            detail=detail,
            payload=json.dumps(parsed.record, default=str)[:2_048] if parsed.record else None,
            origin=origin,
            adapter=adapter.name,
        )

    def _persist(self, events: list[SecurityEvent], report: IngestionReport) -> None:
        """Store events, the batch record and an audit entry."""
        if events:
            repository.save_events(self.session, events)
        # A re-import updates the existing batch row, so the report points at
        # wherever the rejections actually landed.
        batch = repository.save_import_batch(self.session, report)
        report.batch_id = batch.batch_id
        repository.record_audit(
            self.session,
            AuditEntry(
                actor=Actor.SYSTEM,
                action=AuditAction.EVENT_INGESTED,
                object_type="import_batch",
                object_id=report.batch_id,
                after=counted(report.accepted, "event"),
                detail=report.summary(),
            ),
        )


def _hash(data: str | bytes) -> str:
    """Content hash used to recognise a re-import of the same file."""
    payload = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(payload).hexdigest()


def _summarise(error: ValidationError) -> str:
    """Condense a Pydantic error into one readable line."""
    parts = []
    for item in error.errors()[:3]:
        location = ".".join(str(piece) for piece in item["loc"]) or "record"
        parts.append(f"{location}: {item['msg']}")
    if len(error.errors()) > 3:
        parts.append(f"and {len(error.errors()) - 3} more")
    return "; ".join(parts)


def _utcnow() -> Any:
    from app.models.base import utcnow

    return utcnow()
