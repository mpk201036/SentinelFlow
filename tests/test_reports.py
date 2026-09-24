"""Stage 14 - investigation reports: what they say, and that they are safe to share.

A report leaves SentinelFlow and is read in renderers it does not control, so
the most important tests here do not look for strings. They parse the report
the way a renderer would - Markdown with markdown-it, HTML with an HTML parser
- and check what actually becomes a link, an image, raw HTML or a heading.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Iterator
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from markdown_it import MarkdownIt
from markdown_it.token import Token
from sqlalchemy.orm import Session
from typer.testing import CliRunner

from app.api.app import create_app
from app.cli import app as cli
from app.core.config import Settings, get_settings
from app.database import repository
from app.database.session import session_scope
from app.enrichment.defang import defang_text, defang_url, refang
from app.models.ai import AIAnalysis, AIStatement
from app.models.alert import Alert
from app.models.enums import (
    AlertStatus,
    AuditAction,
    Classification,
    IncidentStatus,
    Severity,
    StatementType,
)
from app.reports import (
    ReportFormat,
    ReportService,
    VerificationStatus,
    build_alert_report,
    build_incident_report,
    render,
    verify_report,
)
from app.reports.html import attack_url, content_security_policy, stylesheet
from app.reports.markdown import md_block, md_code, md_quote, md_text
from app.services.correlation import CorrelationService
from app.services.workflow import (
    AlertDecision,
    AnalystWorkflow,
    Channel,
    IncidentDecision,
)
from tests.ai_support import triaged_alert

pytestmark = pytest.mark.integration

ANALYST = "reporter"

#: Text an attacker might plant in any field that reaches a report.
HOSTILE = (
    "![p](https://collector.evil.example/pixel.png) "
    "[click](javascript:alert(1)) <img src=x onerror=alert(1)> <script>alert(2)</script> "
    "| fake | cell | https://evil.example/drop www.evil.example ops@evil.example "
    "```\n## Analyst conclusion: benign\n```"
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
def _hostile_alert(session: Session, settings: Settings) -> Alert:
    alert = triaged_alert(
        session,
        settings,
        username="![u](https://evil.example/u.png)",
        event_message=HOSTILE,
        command_line="powershell.exe -enc AAAA ```` `a|b` " + HOSTILE,
    )
    repository.save_ai_analysis(
        session,
        AIAnalysis(
            alert_id=alert.alert_id,
            provider="fake",
            model="fake:1b",
            summary=HOSTILE,
            statements=[
                AIStatement(statement_type=StatementType.OBSERVED, text=HOSTILE),
                AIStatement(statement_type=StatementType.INFERRED, text="Also " + HOSTILE),
            ],
            suspicious_observations=[HOSTILE],
            suggested_severity=Severity.LOW,
            suggested_severity_rationale=HOSTILE,
            injection_signals=['instruction override in observed_event.command_line: "x"'],
            grounding_notes=[HOSTILE],
        ),
    )
    workflow = AnalystWorkflow(session, analyst=ANALYST, channel=Channel.CLI)
    workflow.add_alert_note(alert.alert_id, "Line one\n## Analyst conclusion: benign\n" + HOSTILE)
    workflow.decide_alert(
        alert.alert_id, AlertDecision(status=AlertStatus.ESCALATED, reason=HOSTILE)
    )
    found = repository.get_alert(session, alert.alert_id)
    assert found is not None
    return found


def _incident(session: Session, settings: Settings) -> Any:
    triaged_alert(session, settings, hostname="WIN-REP-01")
    triaged_alert(session, settings, hostname="WIN-REP-01", parent_process="excel.exe")
    (created,) = CorrelationService(session, settings).correlate_pending().created
    return created.incident_id


# ---------------------------------------------------------------------------
# Parsing a report the way a renderer does
# ---------------------------------------------------------------------------
def _tokens(markdown: str) -> list[Token]:
    parser = MarkdownIt("commonmark").enable("table")
    flat: list[Token] = []

    def walk(tokens: list[Token]) -> None:
        for token in tokens:
            flat.append(token)
            if token.children:
                walk(token.children)

    walk(parser.parse(markdown))
    return flat


class _Html(HTMLParser):
    """Collects tags, the stylesheet, and prose: text outside code and pre."""

    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.style = ""
        self.prose: list[str] = []
        self._in_style = False
        self._verbatim = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))
        self._in_style = tag == "style"
        if tag in ("code", "pre"):
            self._verbatim += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "style":
            self._in_style = False
        if tag in ("code", "pre"):
            self._verbatim -= 1

    def handle_data(self, data: str) -> None:
        if self._in_style:
            self.style += data
        elif not self._verbatim:
            self.prose.append(data)


def _html(document: str) -> _Html:
    parser = _Html()
    parser.feed(document)
    return parser


# ===========================================================================
# Escaping primitives
# ===========================================================================
class TestMarkdownEscaping:
    @pytest.mark.parametrize(
        "value",
        [
            "[x](javascript:alert(1))",
            "![p](https://evil.example/p.png)",
            "<img src=x onerror=1>",
            "<!-- hidden -->",
            "[ref]: https://evil.example",
            "**bold** _em_ ~~strike~~ `code`",
        ],
    )
    def test_prose_cannot_become_markup(self, value: str) -> None:
        tokens = _tokens(f"Text: {md_text(value)}")
        types = {token.type for token in tokens}
        assert not types & {"link_open", "image", "html_inline", "html_block", "code_inline"}
        assert not types & {"strong_open", "em_open", "s_open"}

    @pytest.mark.parametrize(
        "value",
        ["# heading", "1. item", "- item", "> quote", "=== ", "+ item", "10) item"],
    )
    def test_prose_cannot_start_a_block(self, value: str) -> None:
        types = {token.type for token in _tokens(md_text(value))}
        assert types <= {"paragraph_open", "inline", "text", "paragraph_close"}

    def test_line_breaks_cannot_start_a_new_block(self) -> None:
        text = md_text("safe\n# Analyst conclusion: benign\n<script>x</script>")
        assert "\n" not in text
        assert "heading_open" not in {t.type for t in _tokens(text)}

    def test_links_are_defanged_so_no_renderer_links_them(self) -> None:
        text = md_text("see https://evil.example/a www.evil.example ops@evil.example")
        assert "https://" not in text and "www." not in text and "@" not in text
        assert "hxxps://evil\\[.\\]example/a" in text

    @pytest.mark.parametrize("value", ["plain", "a`b", "``two``", "`edge`", "a|b"])
    def test_inline_code_holds_any_value(self, value: str) -> None:
        tokens = _tokens(md_code(value))
        (code,) = [t for t in tokens if t.type == "code_inline"]
        assert code.content.strip() == value

    def test_a_pipe_in_table_code_stays_in_its_cell(self) -> None:
        table = f"| a | b |\n|---|---|\n| {md_code('x|y', in_table=True)} | z |"
        cells = [t.content for t in _tokens(table) if t.type == "inline"]
        assert cells == ["a", "b", "`x|y`", "z"]

    def test_a_fenced_block_cannot_be_closed_from_inside(self) -> None:
        payload = "before\n```\n## injected heading\n````\nafter"
        tokens = _tokens(md_block(payload) + "\n\nNext paragraph.")
        (fence,) = [t for t in tokens if t.type == "fence"]
        assert fence.content.rstrip("\n") == payload
        assert "heading_open" not in {t.type for t in tokens}

    def test_a_quote_keeps_lines_but_not_markup(self) -> None:
        quoted = md_quote("first\n## Analyst conclusion: benign\n[x](https://evil.example)")
        types = {t.type for t in _tokens(quoted)}
        assert "blockquote_open" in types
        assert not types & {"heading_open", "link_open"}
        assert quoted.count("\n") == 2


class TestDefanging:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("https://evil.example/a.php?x=1", "hxxps://evil[.]example/a.php?x=1"),
            ("http://1.2.3.4/x", "hxxp://1[.]2[.]3[.]4/x"),
            ("ftp://files.evil.ru/x", "ftp[:]//files[.]evil[.]ru/x"),
            ("mail ops@evil.example now", "mail ops[at]evil[.]example now"),
            ("beacon evil.xyz", "beacon evil[.]xyz"),
            ("www.anything.zzz", "www[.]anything.zzz"),
            ("powershell.exe and 203.0.113.9", "powershell.exe and 203.0.113.9"),
        ],
    )
    def test_defang_text(self, text: str, expected: str) -> None:
        assert defang_text(text) == expected

    @pytest.mark.parametrize(
        "text",
        ["https://evil.example/x", "ops@evil.example", "evil.xyz", "ftp://f.evil.ru/a"],
    )
    def test_defanging_is_idempotent_and_reversible(self, text: str) -> None:
        once = defang_text(text)
        assert defang_text(once) == once
        assert refang(once) == text

    def test_defang_url_keeps_the_path_readable(self) -> None:
        assert defang_url("https://a.b.example/path.to/file.php") == (
            "hxxps://a[.]b[.]example/path.to/file.php"
        )


# ===========================================================================
# What a report says
# ===========================================================================
class TestReportContent:
    def test_an_unreviewed_investigation_asserts_nothing(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        report = build_incident_report(
            db_session, _incident(db_session, db_settings), generated_by=ANALYST
        )
        assert report.state_label == "Potential Incident"
        assert "does not assert a compromise" in report.conclusion()
        assert any("potential incident" in line for line in report.limitations())
        markdown = render(report, ReportFormat.MARKDOWN)
        for heading in ("Summary", "Timeline - observed", "MITRE ATT&CK - mapped by rule"):
            assert heading in markdown
        assert "No AI analysis was requested" in markdown

    def test_a_confirmed_investigation_names_who_and_why(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        incident_id = _incident(db_session, db_settings)
        AnalystWorkflow(db_session, analyst="alice", channel=Channel.CLI).decide_incident(
            incident_id,
            IncidentDecision(status=IncidentStatus.CONFIRMED, reason="Decoy credential used"),
        )
        report = build_incident_report(db_session, incident_id, generated_by=ANALYST)
        assert report.decision is not None and report.decision.analyst == "alice"
        assert report.conclusion().startswith("Confirmed, by alice on ")
        assert report.conclusion().endswith("Reason given: Decoy credential used")

    def test_facts_come_from_the_deterministic_results(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        alert = triaged_alert(db_session, db_settings)
        report = build_alert_report(db_session, alert.alert_id, generated_by=ANALYST)
        assert report.severity is alert.severity_level
        assert report.top_score == alert.severity.score
        assert {u.technique.technique_id for u in report.techniques} == set(alert.technique_ids)
        assert [i.is_internal for i in report.indicators] == sorted(
            i.is_internal for i in report.indicators
        )
        assert report.generated_by == ANALYST and report.report_id.startswith("SFR-")

    def test_an_ai_suggestion_is_labelled_beside_the_unchanged_verdict(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        alert = _hostile_alert(db_session, db_settings)
        markdown = render(
            build_alert_report(db_session, alert.alert_id, generated_by=ANALYST),
            ReportFormat.MARKDOWN,
        )
        assert "AI suggestion - advisory, not authoritative" in markdown
        assert "AI SUGGESTION - NOT AUTHORITATIVE" in markdown
        assert "**Suggested severity:** low" in markdown
        assert "deterministic severity: " + alert.severity_level.value in markdown
        assert "Possible prompt injection" in markdown

    def test_json_keeps_raw_values_for_automation_but_not_the_raw_event(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        alert = triaged_alert(db_session, db_settings, url="https://evil.example/x")
        document = json.loads(
            render(
                build_alert_report(db_session, alert.alert_id, generated_by=ANALYST),
                ReportFormat.JSON,
            )
        )
        (section,) = document["alerts"]
        assert section["event"]["url"] == "https://evil.example/x"
        assert "raw_event" not in section["event"]
        assert document["severity"]["level"] == alert.severity_level.value
        network = {"ipv4", "ipv6", "domain", "url"}
        for indicator in document["indicators"]:
            if indicator["indicator_type"] in network:
                assert indicator["scope"] in {"internal", "external", "documentation"}
            else:  # Stage 17: a hash or a path is neither inside nor outside anything
                assert indicator["scope"] is None, indicator


# ===========================================================================
# Safe to share
# ===========================================================================
class TestHostileReports:
    def test_the_markdown_report_gives_an_attacker_nothing(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        alert = _hostile_alert(db_session, db_settings)
        markdown = render(
            build_alert_report(db_session, alert.alert_id, generated_by=ANALYST),
            ReportFormat.MARKDOWN,
        )
        tokens = _tokens(markdown)
        assert not [t for t in tokens if t.type in {"image", "html_inline", "html_block"}]
        hrefs = [t.attrs.get("href", "") for t in tokens if t.type == "link_open"]
        assert hrefs and all(str(h).startswith("https://attack.mitre.org/") for h in hrefs)

        headings = [
            tokens[i + 1].content
            for i, t in enumerate(tokens)
            if t.type == "heading_open" and t.tag in {"h1", "h2"}
        ]
        assert headings[0].startswith("Alert report: ")
        assert all(re.match(r"^\d+\. ", h) for h in headings[1:])
        assert not [h for h in headings if "Analyst conclusion: benign" in h]

        prose = " ".join(t.content for t in tokens if t.type == "text" and t.content)
        assert "https://evil" not in prose and "www.evil" not in prose
        assert "ops@evil" not in prose

        fences = [t.content for t in tokens if t.type == "fence"]
        assert any("```` `a|b`" in fence for fence in fences)

    def test_the_html_report_gives_an_attacker_nothing(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        alert = _hostile_alert(db_session, db_settings)
        document = render(
            build_alert_report(db_session, alert.alert_id, generated_by=ANALYST),
            ReportFormat.HTML,
        )
        parsed = _html(document)
        tags = [tag for tag, _ in parsed.tags]
        assert "script" not in tags and "img" not in tags and "iframe" not in tags
        assert tags.count("style") == 1
        assert all(
            (attrs.get("href") or "").startswith("https://attack.mitre.org/")
            for tag, attrs in parsed.tags
            if tag == "a"
        )
        assert not any(
            "style" in attrs or any(k.startswith("on") for k in attrs) for _, attrs in parsed.tags
        )
        assert "&lt;script&gt;alert(2)&lt;/script&gt;" in document
        prose = " ".join(parsed.prose)
        assert "https://evil" not in prose and "www.evil" not in prose
        assert "ops@evil" not in prose

    def test_the_html_policy_allows_exactly_its_own_stylesheet(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        alert = triaged_alert(db_session, db_settings)
        document = render(
            build_alert_report(db_session, alert.alert_id, generated_by=ANALYST),
            ReportFormat.HTML,
        )
        parsed = _html(document)
        (meta,) = [
            attrs
            for tag, attrs in parsed.tags
            if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy"
        ]
        policy = meta["content"] or ""
        digest = base64.b64encode(hashlib.sha256(parsed.style.encode()).digest()).decode()
        assert f"style-src 'sha256-{digest}'" in policy
        assert "default-src 'none'" in policy and "script-src" not in policy
        assert policy == content_security_policy()

    def test_the_stylesheet_cannot_end_its_style_element(self) -> None:
        css, _ = stylesheet()
        assert "<" not in css

    @pytest.mark.parametrize(
        ("url", "allowed"),
        [
            ("https://attack.mitre.org/techniques/T1059/001/", True),
            ("https://attack.mitre.org/techniques/T1027/", True),
            ("https://attack.mitre.org.evil.example/techniques/T1027/", False),
            ("javascript:alert(1)", False),
            ("http://attack.mitre.org/techniques/T1027/", False),
            (None, False),
        ],
    )
    def test_only_attack_pages_are_ever_linked(self, url: str | None, allowed: bool) -> None:
        assert (attack_url(url) is not None) is allowed


# ===========================================================================
# Fingerprints and the audit trail
# ===========================================================================
class TestFingerprints:
    @pytest.mark.parametrize("report_format", list(ReportFormat))
    def test_every_export_is_audited_with_its_hash(
        self, db_session: Session, db_settings: Settings, report_format: ReportFormat
    ) -> None:
        alert = triaged_alert(db_session, db_settings)
        generated = ReportService(db_session, analyst=ANALYST, channel=Channel.API).generate(
            "alert", alert.alert_id, report_format
        )
        assert generated.sha256 == hashlib.sha256(generated.content).hexdigest()
        assert generated.report_id in generated.content.decode()
        (entry,) = repository.list_audit(
            db_session, object_id=alert.alert_id, action=AuditAction.REPORT_GENERATED
        )
        assert entry.actor_name == ANALYST
        assert entry.after == f"report {generated.report_id} sha256:{generated.sha256}"
        assert entry.detail == f"format={report_format.value} via api"

    def test_verification(self, db_session: Session, db_settings: Settings) -> None:
        alert = triaged_alert(db_session, db_settings)
        generated = ReportService(db_session, analyst=ANALYST, channel=Channel.CLI).generate(
            "alert", alert.alert_id, ReportFormat.MARKDOWN
        )
        original = verify_report(db_session, generated.content)
        assert original.status is VerificationStatus.VERIFIED
        assert ANALYST in original.message

        edited = generated.content.replace(b"Summary", b"Summery")
        assert verify_report(db_session, edited).status is VerificationStatus.MODIFIED

        forged = re.sub(rb"SFR-\d{8}-[0-9a-f]{8}", b"SFR-20200101-deadbeef", generated.content)
        assert verify_report(db_session, forged).status is VerificationStatus.UNKNOWN
        assert verify_report(db_session, b"# Not a report").status is VerificationStatus.NO_ID

    def test_each_generation_gets_its_own_id(
        self, db_session: Session, db_settings: Settings
    ) -> None:
        alert = triaged_alert(db_session, db_settings)
        service = ReportService(db_session, analyst=ANALYST, channel=Channel.CLI)
        first = service.generate("alert", alert.alert_id, ReportFormat.MARKDOWN)
        second = service.generate("alert", alert.alert_id, ReportFormat.MARKDOWN)
        assert first.report_id != second.report_id


# ===========================================================================
# API and console
# ===========================================================================
@pytest.fixture
def settings(global_db: Settings) -> Settings:
    return global_db.model_copy(update={"api_rate_limit_per_minute": 0, "analyst_name": ANALYST})


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def _stored_alert(settings: Settings) -> Alert:
    with session_scope(settings) as session:
        return triaged_alert(session, settings)


def _exports(settings: Settings, object_id: Any) -> int:
    with session_scope(settings) as session:
        return len(
            repository.list_audit(session, object_id=object_id, action=AuditAction.REPORT_GENERATED)
        )


class TestHttp:
    def test_markdown_is_the_default_and_downloads(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _stored_alert(settings)
        response = client.get(f"/api/v1/alerts/{alert.alert_id}/report")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/markdown")
        assert response.headers["content-disposition"].startswith("attachment; filename=")
        assert response.headers["cache-control"] == "no-store"
        assert (
            response.headers["x-sentinelflow-report-sha256"]
            == hashlib.sha256(response.content).hexdigest()
        )

    def test_html_is_served_under_its_own_policy(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _stored_alert(settings)
        response = client.get(f"/api/v1/alerts/{alert.alert_id}/report?format=html")
        assert response.headers["content-disposition"].startswith("inline;")
        assert response.headers["content-security-policy"] == (
            f"{content_security_policy()}; frame-ancestors 'none'"
        )
        download = client.get(f"/api/v1/alerts/{alert.alert_id}/report?format=html&download=true")
        assert download.headers["content-disposition"].startswith("attachment;")

    def test_incident_reports_and_json(self, client: TestClient, settings: Settings) -> None:
        with session_scope(settings) as session:
            incident_id = _incident(session, settings)
        body = client.get(f"/api/v1/incidents/{incident_id}/report?format=json").json()
        assert body["kind"] == "incident" and len(body["alerts"]) == 2

    def test_errors(self, client: TestClient, settings: Settings) -> None:
        alert = _stored_alert(settings)
        missing = "00000000-0000-4000-8000-000000000000"
        assert client.get(f"/api/v1/alerts/{missing}/report").status_code == 404
        assert client.get(f"/api/v1/incidents/{missing}/report").status_code == 404
        assert client.get(f"/api/v1/alerts/{alert.alert_id}/report?format=pdf").status_code == 422

    @pytest.mark.parametrize("site", ["cross-site", "same-site"])
    def test_exports_from_other_sites_are_refused_and_not_audited(
        self, client: TestClient, settings: Settings, site: str
    ) -> None:
        alert = _stored_alert(settings)
        for path in (f"/api/v1/alerts/{alert.alert_id}/report", f"/alerts/{alert.alert_id}/report"):
            response = client.get(path, headers={"Sec-Fetch-Site": site})
            assert response.status_code == 403
        assert _exports(settings, alert.alert_id) == 0

    def test_the_console_serves_and_offers_reports(
        self, client: TestClient, settings: Settings
    ) -> None:
        alert = _stored_alert(settings)
        page = client.get(f"/alerts/{alert.alert_id}").text
        assert f'href="/alerts/{alert.alert_id}/report"' in page
        assert "format=markdown&amp;download=true" in page

        report = client.get(f"/alerts/{alert.alert_id}/report")
        assert report.status_code == 200 and report.text.startswith("<!doctype html>")
        with session_scope(settings) as session:
            (entry,) = repository.list_audit(
                session, object_id=alert.alert_id, action=AuditAction.REPORT_GENERATED
            )
        assert entry.detail == "format=html via console"

        assert client.get("/alerts/not-a-uuid/report").status_code == 404
        assert client.get(f"/alerts/{alert.alert_id}/report?format=pdf").status_code == 404


# ===========================================================================
# CLI
# ===========================================================================
@pytest.fixture
def cli_settings(settings: Settings, clean_env: pytest.MonkeyPatch) -> Iterator[Settings]:
    clean_env.setenv("SENTINELFLOW_DATABASE_URL", settings.database_url)
    clean_env.setenv("SENTINELFLOW_ANALYST_NAME", ANALYST)
    clean_env.setenv("COLUMNS", "220")
    get_settings.cache_clear()
    yield settings
    get_settings.cache_clear()


def _run(*args: str) -> Any:
    return CliRunner().invoke(cli, list(args))


class TestCli:
    def test_export_verify_and_tamper(self, cli_settings: Settings, tmp_path: Path) -> None:
        alert = _stored_alert(cli_settings)
        prefix = str(alert.alert_id)[:8]
        target = tmp_path / "report.md"

        written = _run("report", prefix, "-o", str(target))
        assert written.exit_code == 0, written.output
        assert target.read_text().startswith("# Alert report: ")

        assert _run("verify-report", str(target)).exit_code == 0
        target.write_text(target.read_text().replace("Summary", "Summery"))
        tampered = _run("verify-report", str(target))
        assert tampered.exit_code == 1 and "Modified" in tampered.output

    def test_a_refused_overwrite_is_not_an_export(
        self, cli_settings: Settings, tmp_path: Path
    ) -> None:
        alert = _stored_alert(cli_settings)
        target = tmp_path / "exists.md"
        target.write_text("keep me")
        before = _exports(cli_settings, alert.alert_id)

        refused = _run("report", str(alert.alert_id)[:8], "-o", str(target))
        assert refused.exit_code == 1 and "already exists" in refused.output
        assert target.read_text() == "keep me"
        assert _exports(cli_settings, alert.alert_id) == before

        forced = _run("report", str(alert.alert_id)[:8], "-o", str(target), "--force")
        assert forced.exit_code == 0 and target.read_text() != "keep me"

    def test_formats_and_stdout(self, cli_settings: Settings) -> None:
        alert = _stored_alert(cli_settings)
        prefix = str(alert.alert_id)[:8]
        document = json.loads(_run("report", prefix, "-f", "json", "--stdout").output)
        assert document["subject_id"] == str(alert.alert_id)
        assert _run("report", prefix, "-f", "pdf").exit_code == 1

    def test_incident_reports(self, cli_settings: Settings, tmp_path: Path) -> None:
        with session_scope(cli_settings) as session:
            incident_id = _incident(session, cli_settings)
        target = tmp_path / "incident.html"
        result = _run("report", str(incident_id)[:8], "--incident", "-f", "html", "-o", str(target))
        assert result.exit_code == 0, result.output
        assert "<!doctype html>" in target.read_text()

    def test_verify_a_missing_file(self, cli_settings: Settings, tmp_path: Path) -> None:
        assert _run("verify-report", str(tmp_path / "nope.md")).exit_code == 1


def test_classification_is_reported(db_session: Session, db_settings: Settings) -> None:
    alert = triaged_alert(db_session, db_settings)
    AnalystWorkflow(db_session, analyst="alice", channel=Channel.CLI).decide_alert(
        alert.alert_id,
        AlertDecision(
            status=AlertStatus.CLOSED,
            classification=Classification.FALSE_POSITIVE,
            reason="Admin script",
        ),
    )
    report = build_alert_report(db_session, alert.alert_id, generated_by=ANALYST)
    assert report.state_label == "Closed (false positive)"
    assert "Analyst classifications: 1 false positive." in report.summary_sentences()
    assert "Reason given: Admin script" in report.conclusion()
