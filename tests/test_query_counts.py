"""Stage 15 - query counts must not grow with the data.

Measured on first run: the alert queue cost a query per alert, the
investigation page another, and an investigation report three per member
alert (85 queries for 25 alerts). Each page is now loaded twice, over a small
and a larger investigation, and must issue the same number of queries both
times. A page that starts fetching per row fails here long before anyone
notices it in production.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event

from app.api.app import create_app
from app.core.config import Settings
from app.database import repository
from app.database.session import session_scope
from app.models.ai import AIAnalysis
from app.services.correlation import CorrelationService
from app.services.workflow import AnalystWorkflow, Channel
from tests.ai_support import triaged_alert

pytestmark = pytest.mark.integration


@dataclass
class Scenario:
    client: TestClient
    incident_id: UUID
    alert_id: UUID
    counter: dict[str, int]

    def queries(self, path: str) -> int:
        self.counter["n"] = 0
        response = self.client.get(path)
        assert response.status_code == 200, (path, response.status_code)
        return self.counter["n"]


@contextmanager
def _scenario(settings: Settings, size: int) -> Iterator[Scenario]:
    with session_scope(settings) as session:
        for index in range(size):
            alert = triaged_alert(session, settings, hostname="WIN-Q-01", username=f"u{index}")
            # Every alert gets a note and an analysis, so per-alert lookups of
            # either would show up in the count.
            AnalystWorkflow(session, analyst="t", channel=Channel.CLI).add_alert_note(
                alert.alert_id, f"note {index}"
            )
            repository.save_ai_analysis(
                session,
                AIAnalysis(alert_id=alert.alert_id, provider="f", model="m", summary="s"),
            )
        CorrelationService(session, settings).correlate_pending()
        (incident,) = repository.list_incidents(session)
        first = repository.list_alerts(session, limit=1)[0]

    app = create_app(settings)
    counter = {"n": 0}
    with TestClient(app) as client:
        event.listen(
            app.state.engine,
            "before_cursor_execute",
            lambda *args, **kwargs: counter.__setitem__("n", counter["n"] + 1),
        )
        yield Scenario(client, incident.incident_id, first.alert_id, counter)


PAGES = {
    "alert queue": "/alerts",
    "overview": "/",
    "alert page": "/alerts/{alert}",
    "investigation page": "/incidents/{incident}",
    "API alert list": "/api/v1/alerts?limit=200",
    "API investigation": "/api/v1/incidents/{incident}",
    "investigation report": "/api/v1/incidents/{incident}/report",
    "investigation report (JSON)": "/api/v1/incidents/{incident}/report?format=json",
    "alert report": "/api/v1/alerts/{alert}/report",
}


def _counts(settings: Settings, size: int) -> dict[str, int]:
    with _scenario(settings, size) as scenario:
        return {
            name: scenario.queries(
                path.format(alert=scenario.alert_id, incident=scenario.incident_id)
            )
            for name, path in PAGES.items()
        }


@pytest.fixture
def settings(tmp_path: Any, clean_env: pytest.MonkeyPatch) -> Iterator[Any]:
    from app.database.init_db import initialize_database
    from app.database.session import get_engine, reset_engine

    def make(name: str) -> Settings:
        built = Settings(
            _env_file=None,
            database_url=f"sqlite:///{tmp_path / name}.db",
            api_rate_limit_per_minute=0,
        )
        reset_engine()
        initialize_database(get_engine(built))
        return built

    yield make
    reset_engine()


def test_no_page_issues_a_query_per_alert(settings: Any) -> None:
    small = _counts(settings("small"), 3)
    large = _counts(settings("large"), 12)
    growing = {name: (small[name], large[name]) for name in PAGES if large[name] > small[name]}
    assert not growing, f"query count grows with the number of alerts: {growing}"
