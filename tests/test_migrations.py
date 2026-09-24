"""Stage 16 - every migration brings the version before it forward, and is safe to repeat.

docs/architecture.md says each migration is idempotent and tested against a
database at the version before it. Versions 5 and 6 had such tests; 2 to 4
did not, and their code had never run in a test. Each is exercised here: take
a current database, remove what that version adds, stamp the version before
it, migrate, and check that everything is back and nothing was lost.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
import sqlalchemy as sa
from sqlalchemy import Connection, Engine
from sqlalchemy.orm import Session

from app.database import repository
from app.database.init_db import MIGRATIONS, apply_pending_migrations, current_version
from app.database.tables import SCHEMA_VERSION
from tests.ai_support import powershell_event

pytestmark = pytest.mark.integration


def _tables(engine: Engine) -> set[str]:
    return set(sa.inspect(engine).get_table_names())


def _columns(engine: Engine, table: str) -> set[str]:
    return {column["name"] for column in sa.inspect(engine).get_columns(table)}


def _stamp(connection: Connection, version: int) -> None:
    connection.execute(sa.text("DELETE FROM schema_version WHERE version >= :v"), {"v": version})
    connection.execute(
        sa.text(
            "INSERT INTO schema_version (version, description, applied_at) "
            "VALUES (:v, 'rolled back by a test', CURRENT_TIMESTAMP)"
        ),
        {"v": version - 1},
    )


def _drop_ingestion_tables(connection: Connection) -> None:
    connection.execute(sa.text("DROP TABLE rejected_events"))
    connection.execute(sa.text("DROP TABLE import_batches"))


def _drop_event_indicators(connection: Connection) -> None:
    connection.execute(sa.text("DROP TABLE event_indicators"))


def _drop_triaged_at(connection: Connection) -> None:
    connection.execute(sa.text("DROP INDEX IF EXISTS ix_events_triaged_at"))
    connection.execute(sa.text("ALTER TABLE events DROP COLUMN triaged_at"))


#: version -> (how to undo it, how to tell it has been redone)
ROLLBACKS: dict[int, tuple[Callable[[Connection], None], Callable[[Engine], bool]]] = {
    2: (
        _drop_ingestion_tables,
        lambda e: {"import_batches", "rejected_events"} <= _tables(e),
    ),
    3: (_drop_event_indicators, lambda e: "event_indicators" in _tables(e)),
    4: (_drop_triaged_at, lambda e: "triaged_at" in _columns(e, "events")),
}


@pytest.mark.parametrize("version", sorted(ROLLBACKS))
def test_a_database_one_version_back_is_brought_forward(db_engine: Engine, version: int) -> None:
    undo, redone = ROLLBACKS[version]
    with Session(db_engine) as session:
        repository.save_event(session, powershell_event())
        session.commit()
    with db_engine.begin() as connection:
        undo(connection)
        _stamp(connection, version)
    assert current_version(db_engine) == version - 1
    assert not redone(db_engine)

    applied = apply_pending_migrations(db_engine)

    assert applied == list(range(version, SCHEMA_VERSION + 1))
    assert current_version(db_engine) == SCHEMA_VERSION
    assert redone(db_engine)
    with db_engine.connect() as connection:
        assert connection.execute(sa.text("SELECT count(*) FROM events")).scalar() == 1


@pytest.mark.parametrize("migration", MIGRATIONS, ids=lambda m: f"v{m.version}")
def test_every_migration_is_safe_to_repeat(db_engine: Engine, migration: object) -> None:
    upgrade = migration.upgrade  # type: ignore[attr-defined]
    with db_engine.begin() as connection:
        upgrade(connection)
        upgrade(connection)
    assert current_version(db_engine) == SCHEMA_VERSION


def test_the_migrations_are_complete_and_in_order() -> None:
    versions = [m.version for m in MIGRATIONS]
    assert versions == list(range(2, SCHEMA_VERSION + 1))
