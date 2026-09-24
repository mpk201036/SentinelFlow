"""Database creation and schema versioning.

Alembic is the usual answer to migrations, and it is the right answer for a
service with real deployments. For a single-file SQLite database that a
recruiter may clone and run once, it is a dependency, a config file and a
directory of generated scripts standing between "git clone" and "it works".

What is here instead: ``metadata.create_all`` for a fresh database, plus a
``schema_version`` table and an ordered list of migrations for an existing one.
It is idempotent, it is about a hundred lines, and it can be read in full
before trusting it. ``docs/architecture.md`` records the point at which moving
to Alembic becomes the better trade.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import sqlalchemy as sa
from sqlalchemy import Connection, Engine

from app.core.logging import get_logger
from app.database.base import Base
from app.database.session import _sqlite_path, get_engine
from app.database.tables import ALL_TABLES, SCHEMA_VERSION, SchemaVersion
from app.models.base import utcnow

logger = get_logger(__name__)


@dataclass(frozen=True)
class Migration:
    """A single forward schema change."""

    version: int
    description: str
    upgrade: Callable[[Connection], None]


def _add_ingestion_tables(connection: Connection) -> None:
    """Version 2: import batch tracking and the rejected-record quarantine.

    ``create_all`` handles new tables on its own, so this looks redundant on a
    fresh database. It is not redundant on an existing one: running it
    explicitly, and stamping the version, is what records that a database
    created at version 1 has been brought forward rather than merely happening
    to have the right tables.
    """
    tables = [Base.metadata.tables[name] for name in ("import_batches", "rejected_events")]
    Base.metadata.create_all(connection, tables=tables)


def _add_event_indicator_link(connection: Connection) -> None:
    """Version 3: link indicators to every event they were seen in."""
    Base.metadata.create_all(connection, tables=[Base.metadata.tables["event_indicators"]])


def _add_event_triage_marker(connection: Connection) -> None:
    """Version 4: record when the pipeline last processed an event.

    The first migration that ``create_all`` cannot perform, because it alters an
    existing table rather than adding a new one. Guarded so it is safe to run
    against a database that already has the column.
    """
    columns = {row[1] for row in connection.execute(sa.text("PRAGMA table_info(events)"))}
    if "triaged_at" not in columns:
        connection.execute(sa.text("ALTER TABLE events ADD COLUMN triaged_at DATETIME"))
    connection.execute(
        sa.text("CREATE INDEX IF NOT EXISTS ix_events_triaged_at ON events (triaged_at)")
    )


def _add_ai_system_checks(connection: Connection) -> None:
    """Version 5: store SentinelFlow's own checks on AI output.

    The injection signals, grounding notes and per-statement downgrade flag
    are written by SentinelFlow, not by the model, so they get their own
    columns instead of being folded into the model's text.
    """
    additions = {
        "ai_analysis": (
            ("injection_signals", "JSON NOT NULL DEFAULT '[]'"),
            ("grounding_notes", "JSON NOT NULL DEFAULT '[]'"),
        ),
        "ai_statements": (("downgraded", "BOOLEAN NOT NULL DEFAULT 0"),),
    }
    for table, columns in additions.items():
        existing = {row[1] for row in connection.execute(sa.text(f"PRAGMA table_info({table})"))}
        for name, definition in columns:
            if name not in existing:
                connection.execute(sa.text(f"ALTER TABLE {table} ADD COLUMN {name} {definition}"))


#: Ordered migrations applied on top of the baseline.
MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        version=2,
        description="add import_batches and rejected_events",
        upgrade=_add_ingestion_tables,
    ),
    Migration(
        version=3,
        description="add event_indicators",
        upgrade=_add_event_indicator_link,
    ),
    Migration(
        version=4,
        description="add events.triaged_at",
        upgrade=_add_event_triage_marker,
    ),
    Migration(
        version=5,
        description="add AI injection signals, grounding notes and statement downgrades",
        upgrade=_add_ai_system_checks,
    ),
)


@dataclass
class InitReport:
    """What ``initialize_database`` actually did."""

    database_url: str
    created: bool
    dropped: bool
    tables: list[str] = field(default_factory=list)
    version: int = 0
    applied_migrations: list[int] = field(default_factory=list)

    def describe(self) -> str:
        action = "created" if self.created else "already present"
        migrations = (
            f", applied migrations {self.applied_migrations}" if self.applied_migrations else ""
        )
        return f"schema {action} at version {self.version} ({len(self.tables)} tables){migrations}"


def existing_tables(engine: Engine) -> list[str]:
    """Table names currently present in the database."""
    return sorted(sa.inspect(engine).get_table_names())


def current_version(engine: Engine) -> int:
    """Schema version, or ``0`` when the database has never been initialised."""
    if "schema_version" not in existing_tables(engine):
        return 0
    with engine.connect() as connection:
        result = connection.execute(sa.select(sa.func.max(SchemaVersion.version))).scalar()
    return int(result or 0)


def _stamp(connection: Connection, version: int, description: str) -> None:
    """Record that a schema version is in place. Idempotent."""
    connection.execute(sa.delete(SchemaVersion).where(SchemaVersion.version == version))
    connection.execute(
        sa.insert(SchemaVersion).values(
            version=version, description=description, applied_at=utcnow()
        )
    )


def apply_pending_migrations(engine: Engine) -> list[int]:
    """Apply every migration newer than the recorded version."""
    version = current_version(engine)
    applied: list[int] = []
    for migration in sorted(MIGRATIONS, key=lambda m: m.version):
        if migration.version <= version:
            continue
        logger.info("applying migration %s: %s", migration.version, migration.description)
        with engine.begin() as connection:
            migration.upgrade(connection)
            _stamp(connection, migration.version, migration.description)
        applied.append(migration.version)
    return applied


def initialize_database(engine: Engine | None = None, *, drop_existing: bool = False) -> InitReport:
    """Create the schema if it is absent and bring it up to date.

    ``drop_existing`` destroys all stored events, alerts and analyst work. It
    is never the default and the CLI asks for confirmation before passing it.
    """
    engine = engine or get_engine()
    report = InitReport(database_url=str(engine.url), created=False, dropped=False)

    if drop_existing:
        logger.warning("dropping all tables - every stored event and alert will be lost")
        Base.metadata.drop_all(engine)
        report.dropped = True

    before = existing_tables(engine)
    Base.metadata.create_all(engine)
    after = existing_tables(engine)

    report.created = bool(set(after) - set(before))
    report.tables = after

    if current_version(engine) == 0:
        with engine.begin() as connection:
            _stamp(connection, SCHEMA_VERSION, "baseline schema")
        logger.info("database initialised at schema version %s", SCHEMA_VERSION)

    report.applied_migrations = apply_pending_migrations(engine)
    report.version = current_version(engine)

    missing = set(ALL_TABLES) - set(report.tables)
    if missing:  # pragma: no cover - would indicate a broken metadata definition
        raise RuntimeError(f"schema creation incomplete, missing tables: {sorted(missing)}")

    return report


def database_status(engine: Engine | None = None) -> dict[str, Any]:
    """A summary suitable for the CLI and the health endpoint."""
    engine = engine or get_engine()
    tables = existing_tables(engine)
    path = _sqlite_path(str(engine.url))
    status: dict[str, Any] = {
        "database_url": str(engine.url),
        "path": str(path) if path else None,
        "size_bytes": path.stat().st_size if path and path.exists() else None,
        "initialised": "schema_version" in tables,
        "schema_version": current_version(engine),
        "expected_version": SCHEMA_VERSION,
        "table_count": len(tables),
        "foreign_keys_enforced": _foreign_keys_enforced(engine),
    }
    status["up_to_date"] = status["schema_version"] == SCHEMA_VERSION
    if status["initialised"]:
        status["row_counts"] = table_counts(engine)
    return status


def _foreign_keys_enforced(engine: Engine) -> bool:
    """Confirm the pragma actually took effect on a real connection."""
    if not str(engine.url).startswith("sqlite"):
        return True  # pragma: no cover - other backends enforce by default
    with engine.connect() as connection:
        return bool(connection.execute(sa.text("PRAGMA foreign_keys")).scalar())


def table_counts(engine: Engine) -> dict[str, int]:
    """Row count per table, for the CLI and the dashboard footer."""
    counts: dict[str, int] = {}
    present = set(existing_tables(engine))
    with engine.connect() as connection:
        for name in ALL_TABLES:
            table = Base.metadata.tables.get(name)
            if table is None or name not in present:
                continue
            # Built from the Table object, so there is no SQL string to inject
            # into - not even from our own constants.
            query = sa.select(sa.func.count()).select_from(table)
            counts[name] = int(connection.execute(query).scalar() or 0)
    return counts
