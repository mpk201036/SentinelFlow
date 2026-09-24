"""Stage 15 - every CLI command runs, against a real database, without a traceback.

The CLI was the least-tested surface: 34% of it had ever executed in a test,
and it is where Stage 13 found event text crashing the terminal. Each command
here runs once over a database built by ``sentinelflow demo``, and must exit
with the code it documents and never print a Python traceback.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from app.cli import app as cli
from app.core.config import get_settings
from app.database.session import reset_engine

pytestmark = pytest.mark.integration

SAMPLES = Path(__file__).resolve().parents[1] / "data" / "samples"


@pytest.fixture(scope="module")
def demo_env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, str]]:
    """One demo database, shared by every command in this module."""
    directory = tmp_path_factory.mktemp("cli")
    env = {
        "SENTINELFLOW_DATABASE_URL": f"sqlite:///{directory / 'cli.db'}",
        "SENTINELFLOW_ANALYST_NAME": "smoke",
        "SENTINELFLOW_LOG_LEVEL": "WARNING",
        "COLUMNS": "200",
    }
    reset_engine()
    get_settings.cache_clear()
    for args in (["init-db"], ["demo"]):
        result = CliRunner().invoke(cli, args, env=env)
        assert result.exit_code == 0, result.output
    env["REPORT_DIR"] = str(directory)
    yield env
    reset_engine()
    get_settings.cache_clear()


def _run(env: dict[str, str], *args: str) -> Any:
    reset_engine()
    get_settings.cache_clear()
    return CliRunner().invoke(cli, list(args), env=env)


def _first_id(env: dict[str, str], listing: str) -> str:
    output = _run(env, listing).output
    match = re.search(r"\b([0-9a-f]{8})\b", output)
    assert match, output
    return match.group(1)


#: (arguments, expected exit code). ``{alert}``, ``{incident}`` and ``{dir}``
#: are filled in from the demo database.
COMMANDS: list[tuple[list[str], int]] = [
    (["version"], 0),
    (["config"], 0),
    (["db-info"], 0),
    (["adapters"], 0),
    (["rejections"], 0),
    (["indicators"], 0),
    (["indicators", "--frequent", "--external"], 0),
    (["indicators", "--type", "domain"], 0),
    (["indicators", "--type", "nonsense"], 1),
    (["extract"], 0),
    (["rules"], 0),
    (["rules", "--validate"], 0),
    (["rules", "--by-technique"], 0),
    (["rules", "--sync"], 0),
    (["detect"], 0),
    (["mitre"], 0),
    (["mitre", "--coverage"], 0),
    (["mitre", "--technique", "T1059.001"], 0),
    (["mitre", "--technique", "T9999"], 1),
    (["triage"], 0),
    (["alerts"], 0),
    (["alerts", "--open"], 0),
    (["alert", "{alert}"], 0),
    (["alert", "ffffffff"], 1),
    (["correlate"], 0),
    (["incidents"], 0),
    (["incident", "{incident}"], 0),
    (["decide", "{alert}", "--status", "investigating", "--assign", "me"], 0),
    (["decide", "{alert}", "--status", "closed"], 1),
    (["note", "{alert}", "Smoke test note."], 0),
    (["history", "{alert}"], 0),
    (["history", "{incident}", "--incident"], 0),
    (["report", "{alert}", "--stdout"], 0),
    (["report", "{incident}", "--incident", "-f", "html", "-o", "{dir}/smoke.html"], 0),
    (["verify-report", "{dir}/smoke.html"], 0),
    (["import", str(SAMPLES / "firewall.csv"), "--dry-run"], 0),
    # One good record among five bad ones: a partial import succeeds, and
    # every rejection is listed with its reason.
    (["import", str(SAMPLES / "malformed.json")], 0),
    # Always with --out: the default is data/samples, the committed samples.
    (["generate", "--normal", "5", "--out", "{dir}/generated"], 0),
    (["ai", "status"], 0),
    (["ai", "analyze", "{alert}"], 1),
    (["serve", "--host", "0.0.0.0"], 2),
]


@pytest.mark.parametrize(
    ("args", "expected"),
    COMMANDS,
    ids=[" ".join(a for a in args if "{" not in a and "/" not in a) for args, _ in COMMANDS],
)
def test_every_command_runs_cleanly(
    demo_env: dict[str, str], args: list[str], expected: int
) -> None:
    values = {
        "alert": _first_id(demo_env, "alerts"),
        "incident": _first_id(demo_env, "incidents"),
        "dir": demo_env["REPORT_DIR"],
    }
    filled = [arg.format(**values) for arg in args]
    result = _run(demo_env, *filled)
    assert "Traceback" not in result.output, result.output
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        raise result.exception
    assert result.exit_code == expected, result.output


def test_doctor_reports_on_a_working_install(demo_env: dict[str, str]) -> None:
    result = _run(demo_env, "doctor")
    assert "Traceback" not in result.output
    assert "database schema" in result.output
