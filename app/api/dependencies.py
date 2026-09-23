"""Shared FastAPI dependencies."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Query
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.database.session import session_scope
from app.detection import RuleSet, load_rules
from app.mitre import Catalogue, get_catalogue


def db_session() -> Iterator[Session]:
    """One transactional session per request, committed on success."""
    with session_scope() as session:
        yield session


def settings_dependency() -> Settings:
    return get_settings()


def rule_set() -> RuleSet:
    """Rules, reloaded per request.

    Deliberately not cached: editing a rule file and seeing the change without
    restarting is most of what makes rules-as-data worth having. The files are
    small and local, so the cost is negligible.
    """
    return load_rules(get_settings().rules_dir)


def catalogue() -> Catalogue:
    return get_catalogue()


@dataclass
class Pagination:
    """Bounded pagination. One request cannot ask for everything."""

    limit: int
    offset: int


def pagination(
    limit: Annotated[int, Query(ge=1, le=200, description="Maximum records to return.")] = 50,
    offset: Annotated[int, Query(ge=0, le=1_000_000, description="Records to skip.")] = 0,
) -> Pagination:
    return Pagination(limit=limit, offset=offset)


SessionDep = Annotated[Session, Depends(db_session)]
SettingsDep = Annotated[Settings, Depends(settings_dependency)]
RulesDep = Annotated[RuleSet, Depends(rule_set)]
CatalogueDep = Annotated[Catalogue, Depends(catalogue)]
PageDep = Annotated[Pagination, Depends(pagination)]
