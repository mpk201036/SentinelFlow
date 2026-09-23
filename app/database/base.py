"""Declarative base, naming conventions and SQLite-safe column types.

Two details here are easy to get wrong and expensive to discover later.

**Timezones.** SQLite has no timezone-aware datetime type. A plain
``DateTime(timezone=True)`` column silently returns a *naive* datetime on read,
so a timestamp written as 13:42 UTC comes back as 13:42 "local" and every
correlation window quietly shifts. :class:`UtcDateTime` stores UTC and
guarantees an aware UTC value on the way back out.

**Enum storage.** SQLAlchemy stores Python enums by *name* by default, so
``Severity.HIGH`` would be written as ``"HIGH"`` while the JSON API emits
``"high"``. Every enum column here uses ``values_callable`` so the database and
the API agree, and ``native_enum=False`` so SQLite gets a ``VARCHAR`` plus a
``CHECK`` constraint — the database rejects a value outside the vocabulary.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import sqlalchemy as sa
from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.types import TypeDecorator

#: Predictable constraint names, so migrations can reference them by name
#: instead of by whatever the database happened to invent.
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class UtcDateTime(TypeDecorator[datetime]):
    """A datetime column that is always UTC and always timezone-aware."""

    impl = sa.DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


def enum_column(enum_class: type[StrEnum], name: str, length: int = 64) -> sa.Enum:
    """A string column constrained to an enum's *values*.

    ``native_enum=False`` keeps this portable and gives SQLite a CHECK
    constraint, so an invalid status cannot be written even by raw SQL.
    """
    return sa.Enum(
        enum_class,
        name=name,
        native_enum=False,
        # create_constraint defaults to False in SQLAlchemy 1.4+, which would
        # silently reduce this to a plain VARCHAR with no enforcement at all.
        create_constraint=True,
        length=length,
        values_callable=lambda members: [member.value for member in members],
        validate_strings=True,
    )


class Base(DeclarativeBase):
    """Base class for every ORM table."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    def __repr__(self) -> str:  # pragma: no cover - debugging convenience
        pk = self.__mapper__.primary_key[0].name
        return f"<{type(self).__name__} {pk}={getattr(self, pk, None)!r}>"
