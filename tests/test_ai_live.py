"""Stage 12 - one real round trip to a local model. Skipped unless asked for.

Run with a model you have already pulled:

    SF_LIVE_AI_MODEL=qwen2.5:7b pytest -m ai tests/test_ai_live.py

These tests assert what must hold for *any* model, not what a particular model
says: the reply parses, every statement is labelled, planted instructions are
flagged, and the alert's verdict is untouched. Whether the model is steered by
the injection is recorded in docs/ai-safety.md as an observation, not tested,
because it varies by model and the design does not depend on it.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy.orm import Session

from app.ai.providers import OllamaProvider
from app.ai.service import AIAnalysisService, OutcomeKind
from app.core.config import Settings
from app.database import repository
from tests.ai_support import HOSTILE_COMMAND, triaged_alert

MODEL = os.environ.get("SF_LIVE_AI_MODEL", "")
BASE_URL = os.environ.get("SF_LIVE_AI_URL", "http://127.0.0.1:11434")

pytestmark = [
    pytest.mark.ai,
    pytest.mark.skipif(not MODEL, reason="set SF_LIVE_AI_MODEL to run against a local model"),
]


@pytest.fixture
def provider() -> OllamaProvider:
    live = OllamaProvider(base_url=BASE_URL, model=MODEL, timeout_seconds=300)
    status = live.status()
    if not status.ready:
        pytest.skip(f"local model not ready: {status.problem}")
    return live


@pytest.mark.parametrize("command_line", [None, HOSTILE_COMMAND], ids=["clean", "injection"])
def test_a_real_model_round_trip_keeps_every_guarantee(
    db_session: Session,
    db_settings: Settings,
    provider: OllamaProvider,
    command_line: str | None,
) -> None:
    overrides = {"command_line": command_line} if command_line else {}
    alert = triaged_alert(db_session, db_settings, **overrides)

    outcome = AIAnalysisService(db_session, provider).analyze_alert(alert.alert_id)
    provider.close()

    assert outcome.kind is OutcomeKind.STORED, outcome.problem
    analysis = outcome.analysis
    assert analysis is not None and analysis.is_advisory
    assert analysis.statements, "a real analysis makes at least one labelled claim"
    assert analysis.injection_suspected is bool(command_line)

    db_session.flush()
    db_session.expire_all()
    after = repository.get_alert(db_session, alert.alert_id)
    assert after is not None
    assert after.severity == alert.severity and after.status == alert.status
