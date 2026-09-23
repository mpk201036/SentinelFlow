"""Persistence layer.

base        declarative base, UTC-safe datetimes, enum columns
tables      ORM schema
session     engine, pragmas, transactional session scope
init_db     schema creation and versioning
mappers     domain model <-> row conversion
repository  the only API the rest of the application uses
"""

from app.database.base import Base, UtcDateTime
from app.database.init_db import (
    Migration,
    current_version,
    database_status,
    initialize_database,
    table_counts,
)
from app.database.session import (
    create_db_engine,
    get_db_session,
    get_engine,
    get_session_factory,
    reset_engine,
    session_scope,
)
from app.database.tables import SCHEMA_VERSION

__all__ = [
    "SCHEMA_VERSION",
    "Base",
    "Migration",
    "UtcDateTime",
    "create_db_engine",
    "current_version",
    "database_status",
    "get_db_session",
    "get_engine",
    "get_session_factory",
    "initialize_database",
    "reset_engine",
    "session_scope",
    "table_counts",
]
