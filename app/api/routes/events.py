"""Event endpoints: the collection, and the two ways into it.

``POST /events`` takes a JSON batch in any supported source format.
``POST /events/import`` takes a file upload - JSON, NDJSON or CSV.

Neither endpoint accepts a filesystem path. The upload arrives as content, and
its filename is used for one thing only: choosing a parser by extension. It is
never opened, joined to a directory or written anywhere, so there is no
traversal sink reachable from the network to defend.

Both are idempotent by content: re-sending a byte-identical batch is a no-op
that says so, because a retry by a sender that missed the first response must
not double every event in it. Both return ``201`` when they created events and
``200`` when they did not - a duplicate, or a batch in which every record was
rejected with a stated reason.
"""

from __future__ import annotations

from pathlib import PurePath
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, File, Form, HTTPException, Query, Response, UploadFile, status

from app.api import converters, schemas
from app.api.dependencies import CatalogueDep, PageDep, RulesDep, SessionDep, SettingsDep
from app.core.paths import FileTooLargeError
from app.core.sanitize import clean_line
from app.database import repository
from app.ingestion.adapters import UnknownAdapterError
from app.ingestion.service import CSV_SUFFIXES, JSON_SUFFIXES, IngestionOutcome, IngestionService
from app.models.enums import EventType
from app.models.event import hostname_key, username_key
from app.models.ingestion import RejectionReason
from app.services.pipeline import TriagePipeline

router = APIRouter(prefix="/events", tags=["events"])


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------
@router.get("", response_model=schemas.Page[schemas.EventSummary])
def list_events(
    session: SessionDep,
    page: PageDep,
    source: Annotated[str | None, Query(max_length=64)] = None,
    event_type: EventType | None = None,
    hostname: Annotated[str | None, Query(max_length=256)] = None,
    username: Annotated[str | None, Query(max_length=256)] = None,
) -> schemas.Page[schemas.EventSummary]:
    # Normalised exactly as storage normalises: "LAB\\lab-user" and
    # "lab-user" are one account, and a filter that disagreed with storage
    # would quietly find nothing.
    host = hostname_key(hostname)
    account = username_key(username)
    events = repository.list_events(
        session,
        source=source,
        event_type=event_type,
        hostname_key=host,
        username_key=account,
        limit=page.limit,
        offset=page.offset,
    )
    total = repository.count_events_matching(
        session, source=source, event_type=event_type, hostname_key=host, username_key=account
    )
    return schemas.Page(
        items=[converters.event_summary(e) for e in events],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/{event_id}", response_model=schemas.EventDetail)
def get_event(event_id: UUID, session: SessionDep) -> schemas.EventDetail:
    event = repository.get_event(session, event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="event not found")
    return converters.event_detail(event)


# ---------------------------------------------------------------------------
# Ingesting
# ---------------------------------------------------------------------------
def _complete(
    outcome: IngestionOutcome,
    response: Response,
    *,
    triage: bool,
    session: SessionDep,
    settings: SettingsDep,
    rules: RulesDep,
    catalogue: CatalogueDep,
) -> schemas.IngestResponse:
    """Shared tail of both ingestion routes: refuse, triage, report."""
    if any(r.reason is RejectionReason.UNKNOWN_SOURCE for r in outcome.report.rejections):
        raise UnknownAdapterError(outcome.report.rejections[0].detail)

    alerts_created = 0
    if triage and outcome.events:
        result = TriagePipeline(session, settings, rules=rules, catalogue=catalogue).process(
            outcome.events
        )
        alerts_created = result.alerts_created

    created = outcome.accepted > 0 and not outcome.report.duplicate_batch
    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    return converters.ingestion(outcome.report, alerts_created=alerts_created)


@router.post(
    "",
    response_model=schemas.IngestResponse,
    status_code=status.HTTP_201_CREATED,
    responses={200: {"description": "Nothing new: a duplicate batch, or every record rejected"}},
)
def ingest_events(
    body: schemas.IngestRequest,
    response: Response,
    session: SessionDep,
    settings: SettingsDep,
    rules: RulesDep,
    catalogue: CatalogueDep,
) -> schemas.IngestResponse:
    """Ingest a JSON batch, then run triage on it unless ``triage`` is false."""
    outcome = IngestionService(session, settings).ingest_mappings(
        body.events, adapter_name=body.source, origin="api", force=body.force
    )
    return _complete(
        outcome,
        response,
        triage=body.triage,
        session=session,
        settings=settings,
        rules=rules,
        catalogue=catalogue,
    )


@router.post(
    "/import",
    response_model=schemas.IngestResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        200: {"description": "Nothing new: a duplicate file, or every record rejected"},
        413: {"model": schemas.ErrorResponse, "description": "File exceeds the upload limit"},
        415: {"model": schemas.ErrorResponse, "description": "Not a JSON, NDJSON or CSV file"},
    },
)
def import_file(
    response: Response,
    session: SessionDep,
    settings: SettingsDep,
    rules: RulesDep,
    catalogue: CatalogueDep,
    file: Annotated[UploadFile, File(description="A JSON, NDJSON or CSV export.")],
    source: Annotated[str | None, Form(max_length=64)] = None,
    triage: Annotated[bool, Form()] = True,
    force: Annotated[bool, Form()] = False,
) -> schemas.IngestResponse:
    """Ingest an uploaded export file."""
    # The filename picks a parser and labels the batch. Nothing else: only its
    # final component survives, and it is never used to touch the filesystem.
    name = clean_line(PurePath(file.filename or "upload").name, max_length=128) or "upload"
    suffix = PurePath(name).suffix.lower()
    if suffix not in JSON_SUFFIXES | CSV_SUFFIXES:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"unsupported file type {suffix or '(none)'!r}; send "
            + ", ".join(sorted(JSON_SUFFIXES | CSV_SUFFIXES)),
        )

    # Read one byte past the limit, so an oversized file is refused without
    # ever being held in memory whole. The body-size middleware is the first
    # check; this is the second, and it does not depend on a header.
    limit = settings.max_upload_bytes
    data = file.file.read(limit + 1)
    if len(data) > limit:
        raise FileTooLargeError(f"{name} exceeds the {limit:,} byte upload limit")

    service = IngestionService(session, settings)
    origin = f"upload:{name}"
    if suffix in CSV_SUFFIXES:
        outcome = service.ingest_csv(data, adapter_name=source, origin=origin, force=force)
    else:
        outcome = service.ingest_json(data, adapter_name=source, origin=origin, force=force)

    return _complete(
        outcome,
        response,
        triage=triage,
        session=session,
        settings=settings,
        rules=rules,
        catalogue=catalogue,
    )
