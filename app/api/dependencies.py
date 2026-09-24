"""Shared FastAPI dependencies.

Every dependency reads from the application that is serving the request -
``request.app.state`` - never from process-wide globals. An app built with
``create_app(settings)`` therefore serves requests with *those* settings and
*that* database. Before this was true, the factory configured its middleware
from the settings it was given and then every handler quietly read the
defaults instead.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Annotated

from fastapi import Depends, Query, Request
from sqlalchemy.orm import Session

from app.ai.providers import ModelProvider
from app.core.config import Settings
from app.detection import RuleSet, load_rules
from app.mitre import Catalogue, get_catalogue


def db_session(request: Request) -> Iterator[Session]:
    """One transactional session per request: commit on success, roll back on error."""
    session: Session = request.app.state.session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def settings_dependency(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def rule_set(request: Request) -> RuleSet:
    """Rules, reloaded per request.

    Deliberately not cached: editing a rule file and seeing the change without
    restarting is most of what makes rules-as-data worth having. The files are
    small and local, so the cost is negligible.
    """
    return load_rules(request.app.state.settings.rules_dir)


def catalogue() -> Catalogue:
    return get_catalogue()


@dataclass
class AIState:
    """The app's model provider, or the reason it has none.

    ``lock`` allows one analysis at a time. A local model shares one GPU, so
    a second request would only slow the first down, and an unbounded queue
    of them is a cheap way to make the console unusable.
    """

    provider: ModelProvider | None
    problem: str | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)


def ai_state(request: Request) -> AIState:
    state: AIState = request.app.state.ai
    return state


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
AIDep = Annotated[AIState, Depends(ai_state)]
