"""Stage 17 - the demonstration, end to end, exactly as docs/demo-scenario.md tells it.

The brief asked for one full demonstration: authentication failures, a
successful login, PowerShell, a file download and an administrative account
change, which SentinelFlow must ingest, detect, correlate, map, score, turn
into an investigation, display and report on.

Everything here runs through the interfaces a person uses: the real
``sentinelflow demo`` command, the console over HTTP, and the walkthrough's
own command block, executed line by line. The walkthrough's tables are read
from the page and compared with what the run produced, so the page cannot
drift from the product.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker
from typer.testing import CliRunner

from app.api.app import create_app
from app.cli import app as cli
from app.core.config import Settings, get_settings
from app.database import repository
from app.database.session import create_db_engine, reset_engine
from app.ingestion import demo_base_time, generate_demo_scenario, get_adapter
from app.models.alert import Alert
from app.models.enums import AlertStatus, IncidentStatus
from app.models.event import SecurityEvent

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[1]
PAGE = (ROOT / "docs" / "demo-scenario.md").read_text(encoding="utf-8")
#: A pinned clock for the run. The demo anchors itself to the night before, so
#: any time of day gives the same result; pinning just makes it exact.
NOW = datetime(2026, 9, 23, 14, 30, tzinfo=UTC)


@dataclass
class Demo:
    env: dict[str, str]
    settings: Settings
    session: Session
    alerts: list[Alert]  # in event time
    events: dict[Any, SecurityEvent]
    directory: Path

    def event(self, alert: Alert) -> SecurityEvent:
        return self.events[alert.primary_event_id]

    def run(self, *args: str) -> Any:
        reset_engine()
        get_settings.cache_clear()
        result = CliRunner().invoke(cli, list(args), env=self.env)
        assert "Traceback" not in result.output, result.output
        return result


@pytest.fixture(scope="module")
def demo(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Demo]:
    directory = tmp_path_factory.mktemp("demo")
    url = f"sqlite:///{directory / 'demo.db'}"
    env = {
        "SENTINELFLOW_DATABASE_URL": url,
        "SENTINELFLOW_ANALYST_NAME": "walkthrough",
        "SENTINELFLOW_LOG_LEVEL": "WARNING",
        "COLUMNS": "200",
    }
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("app.cli.demo_base_time", lambda: demo_base_time(NOW))
        reset_engine()
        get_settings.cache_clear()
        result = CliRunner().invoke(cli, ["demo"], env=env)
    assert result.exit_code == 0, result.output

    settings = Settings(_env_file=None, database_url=url, analyst_name="walkthrough")
    engine = create_db_engine(settings)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    events = {e.event_id: e for e in repository.list_events(session, limit=1_000)}
    alerts = sorted(
        repository.list_alerts(session, limit=1_000),
        key=lambda a: events[a.primary_event_id].timestamp,
    )
    yield Demo(env, settings, session, alerts, events, directory)
    session.close()
    engine.dispose()
    reset_engine()
    get_settings.cache_clear()


def _key(event: SecurityEvent) -> tuple[str, ...]:
    return (event.timestamp.isoformat(), event.source, event.event_type.value, event.hostname or "")


def _scenario_keys() -> set[tuple[str, ...]]:
    """What the intrusion's own events are, regenerated with the run's clock."""
    start = demo_base_time(NOW) + timedelta(hours=5)
    records = generate_demo_scenario(start)
    return {_key(get_adapter(r.adapter).normalise(r.record)) for r in records}


def _table(heading: str) -> list[list[str]]:
    """The body rows of the first Markdown table after a heading."""
    section = PAGE.split(heading, 1)[1]
    rows = []
    for line in section.splitlines():
        if line.startswith("|"):
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if not set("".join(cells)) <= set("-: "):
                rows.append(cells)
        elif rows:
            break
    return rows[1:]  # without the header


def _block(heading: str) -> list[str]:
    """The command lines of the first bash block after a heading."""
    section = PAGE.split(heading, 1)[1]
    block = section.split("```bash\n", 1)[1].split("```", 1)[0]
    return [re.sub(r"\s+#\s.*$", "", line).strip() for line in block.splitlines() if line]


# ===========================================================================
# The page's tables are what the run produced
# ===========================================================================
def test_the_timeline_table_is_what_the_demo_produces(demo: Demo) -> None:
    documented = [
        (
            row[0],
            re.findall(r"SF-\d{4}", row[3]),
            sorted(re.findall(r"T\d{4}(?:\.\d{3})?", row[4])),
            row[5],
        )
        for row in _table("## What happened, and what fired")
    ]
    produced = [
        (
            demo.event(alert).timestamp.strftime("%H:%M:%S"),
            sorted(alert.rule_ids),
            sorted(alert.technique_ids),
            f"{alert.severity.score} {alert.severity_level.value}",
        )
        for alert in demo.alerts
    ]
    assert documented == produced


def test_the_numbers_at_a_glance(demo: Demo) -> None:
    documented = {
        row[0]: [int(n) for n in re.findall(r"\d+", row[1])] for row in _table("## At a glance")
    }

    events = list(demo.events.values())
    scenario = _scenario_keys()
    alerted = {alert.primary_event_id for alert in demo.alerts}
    background = [e for e in events if _key(e) not in scenario]
    bands = {"critical": 0, "high": 0, "medium": 0}
    for alert in demo.alerts:
        bands[alert.severity_level.value] += 1
    techniques = {m.technique.technique_id: m.technique for a in demo.alerts for m in a.mitre}
    tactics = {tactic for t in techniques.values() for tactic in t.tactics}
    incidents = repository.list_incidents(demo.session, limit=10)
    members = repository.list_alerts(demo.session, incident_id=incidents[0].incident_id)
    span = demo.event(demo.alerts[-1]).timestamp - demo.event(demo.alerts[0]).timestamp

    assert len(events) - len(background) == len(scenario)
    assert documented == {
        "Events ingested": [len(events), len({e.source for e in events}), 0],
        "Background events that raised an alert": [
            len([e for e in background if e.event_id in alerted]),
            len(background),
        ],
        "Alerts": [len(demo.alerts), bands["critical"], bands["high"], bands["medium"]],
        "ATT&CK techniques": [len(techniques), len(tactics)],
        "Potential Incidents": [len(incidents), len(members), int(span.total_seconds() // 60)],
    }
    assert repository.list_rejections(demo.session) == []


def test_the_worked_score_is_the_real_one(demo: Demo) -> None:
    """The page adds one alert's factors up by hand. They must be its factors."""
    documented = {
        row[0].strip("`"): int(row[1])
        for row in _table("### How one score was reached")
        if row[0].startswith("`")
    }
    (alert,) = [a for a in demo.alerts if "SF-0006" in a.rule_ids]
    assert documented == {f.name: f.points for f in alert.severity.factors}
    assert sum(documented.values()) == 110
    assert alert.severity.score == 100


# ===========================================================================
# What the brief asked the demonstration to show
# ===========================================================================
#: The brief's five steps, and the rules that must see each one.
BRIEF = {
    "several authentication failures": {"SF-0001"},
    "successful login": {"SF-0002"},
    "PowerShell execution": {"SF-0003"},
    "file download event": {"SF-0011", "SF-0008"},
    "administrative account change": {"SF-0005", "SF-0006"},
}


@pytest.mark.parametrize("step", BRIEF)
def test_every_step_of_the_brief_is_detected(demo: Demo, step: str) -> None:
    fired = {rule for alert in demo.alerts for rule in alert.rule_ids}
    assert BRIEF[step] <= fired


def test_every_alert_is_mapped_and_scored_with_reasons(demo: Demo) -> None:
    for alert in demo.alerts:
        assert alert.severity.method == "deterministic"
        assert alert.severity.factors
        for mapping in alert.mitre:
            assert mapping.reason and mapping.source_rule_id in alert.rule_ids


def test_nothing_is_mapped_that_no_rule_saw(demo: Demo) -> None:
    """The page says T1105 and T1133 are not claimed. Neither may appear."""
    mapped = {t for alert in demo.alerts for t in alert.technique_ids}
    assert not mapped & {"T1105", "T1133"}


def test_only_the_intrusion_raises_alerts(demo: Demo) -> None:
    scenario = _scenario_keys()
    assert all(_key(demo.event(alert)) in scenario for alert in demo.alerts)


def test_the_attack_becomes_one_potential_incident(demo: Demo) -> None:
    (incident,) = repository.list_incidents(demo.session, limit=10)
    assert incident.status is IncidentStatus.POTENTIAL
    assert set(incident.alert_ids) == {alert.alert_id for alert in demo.alerts}
    assert incident.title.startswith("Decoy credential accessed and 8 related alerts")
    assert (incident.summary or "").endswith("and 3 more.")


def test_the_console_displays_the_investigation(demo: Demo) -> None:
    (incident,) = repository.list_incidents(demo.session, limit=10)
    with TestClient(create_app(demo.settings)) as client:
        page = client.get(f"/incidents/{incident.incident_id}")
        assert page.status_code == 200
        for alert in demo.alerts:
            assert alert.title in page.text
        assert "Potential incident." in page.text

        (decoy,) = [a for a in demo.alerts if "SF-0009" in a.rule_ids]
        detail = client.get(f"/alerts/{decoy.alert_id}").text
        for factor in ("deception_signal", "out_of_hours", "repeat_activity"):
            assert factor in detail


# ===========================================================================
# The analyst's side, run exactly as the page writes it
# ===========================================================================
def test_the_walkthrough_commands_run_as_written(demo: Demo) -> None:
    (incident,) = repository.list_incidents(demo.session, limit=10)
    (decoy,) = [a for a in demo.alerts if "SF-0009" in a.rule_ids]
    ids = {"<incident-id>": str(incident.incident_id)[:8], "<alert-id>": str(decoy.alert_id)[:8]}

    for line in _block("## Work it as an analyst"):
        for placeholder, value in ids.items():
            line = line.replace(placeholder, value)
        args = shlex.split(line)
        assert args[0] == "sentinelflow", line
        result = demo.run(*args[1:])
        assert result.exit_code == 0, f"{line}\n{result.output}"

    demo.session.expire_all()
    stored = repository.get_incident(demo.session, incident.incident_id)
    assert stored is not None and stored.status is IncidentStatus.CONFIRMED
    assert stored.assigned_to == "walkthrough"  # "-a me"
    escalated = repository.get_alert(demo.session, decoy.alert_id)
    assert escalated is not None and escalated.status is AlertStatus.ESCALATED
    for other in demo.alerts:
        if other.alert_id != decoy.alert_id:  # confirming did not decide its alerts
            untouched = repository.get_alert(demo.session, other.alert_id)
            assert untouched is not None and untouched.status is AlertStatus.NEW

    # Then the report, as "Report it" writes it, into a temporary file.
    report, verify = _block("## Report it")
    path = demo.directory / "walkthrough.html"
    for placeholder, value in ids.items():
        report = report.replace(placeholder, value)
    made = demo.run(*shlex.split(report)[1:], "-o", str(path))
    assert made.exit_code == 0, made.output
    assert verify.startswith("sentinelflow verify-report ")
    checked = demo.run("verify-report", str(path))
    assert checked.exit_code == 0 and "SHA-256" in checked.output

    markdown = demo.run(
        "report", ids["<incident-id>"], "--incident", "-f", "markdown", "--stdout"
    ).output
    assert "Confirmed, by walkthrough" in markdown
    assert "updates[.]example" in markdown
    assert "documentation range" in markdown
    assert "awaiting analyst review" not in markdown
