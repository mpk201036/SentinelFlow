"""Stage 11 - the analyst console.

Three kinds of test live here:

* geometry: the chart arithmetic, which is plain Python precisely so that a
  bar 3px too tall is a failing test rather than a screenshot argument;
* rendering: every page returns, empty states hold, the strata of trust appear
  in order and the AI layer stays labelled;
* security: attacker-controlled event fields must render inert, and no
  template may carry the inline script or style the Content-Security-Policy
  exists to forbid. That last one is a property of the source tree, so it is
  checked against the source tree.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from markupsafe import Markup

from app.api.app import create_app
from app.core.config import Settings
from app.database import repository
from app.database.session import session_scope
from app.ingestion import generate_demo_scenario, get_adapter
from app.models.ai import AIAnalysis, AIStatement
from app.models.alert import AlertSeverity, SeverityFactor
from app.models.enums import Severity, StatementType
from app.models.event import SecurityEvent
from app.services import CorrelationService, TriagePipeline
from app.services.dashboard import collect_dashboard_stats, resolve_range
from app.web import STATIC_DIR, TEMPLATE_DIR, charts, templates
from app.web.formatting import FILTERS, ago, compact, humanise, pretty_json

T0 = datetime(2026, 9, 23, 9, 25, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def console_settings(global_db: Settings) -> Settings:
    # Rate limiting off: a test suite is exactly the burst it exists to stop.
    return global_db.model_copy(update={"api_rate_limit_per_minute": 0})


@pytest.fixture
def client(console_settings: Settings) -> Iterator[TestClient]:
    # As a context manager, so the app's lifespan runs and disposes its engine.
    with TestClient(create_app(console_settings)) as test_client:
        yield test_client


def _run_pipeline(settings: Settings, events: list[SecurityEvent]) -> None:
    with session_scope(settings) as session:
        repository.save_events(session, events)
        TriagePipeline(session, settings).process(events)
        CorrelationService(session, settings).correlate_pending()


@pytest.fixture
def demo(console_settings: Settings) -> Iterator[Settings]:
    events = [get_adapter(r.adapter).normalise(r.record) for r in generate_demo_scenario()]
    _run_pipeline(console_settings, events)
    yield console_settings


def _first_alert_id(settings: Settings, **filters: object) -> str:
    with session_scope(settings) as session:
        return str(repository.list_alerts(session, limit=50, **filters)[0].alert_id)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Geometry
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestPaths:
    def test_a_column_rounds_its_top_and_keeps_a_square_base(self) -> None:
        path = charts.column_path(10, 20, 24, 60, rounded=True)
        assert path.startswith("M10,80V24")  # starts at the square base corner
        assert path.count("A") == 2  # two rounded top corners
        assert path.endswith("V80Z")  # returns to the base, square

    def test_a_lower_stack_segment_is_square_at_both_ends(self) -> None:
        assert "A" not in charts.column_path(10, 20, 24, 60, rounded=False)

    def test_a_bar_rounds_its_data_end_only(self) -> None:
        path = charts.bar_path(0, 0, 100, 16, rounded=True)
        assert path.startswith("M0,0H96")
        assert path.endswith("H0Z")  # left end square

    def test_degenerate_marks_draw_nothing(self) -> None:
        assert charts.column_path(0, 0, 10, 0, rounded=True) == ""
        assert charts.bar_path(0, 0, 0, 10, rounded=True) == ""

    def test_the_radius_never_exceeds_a_short_mark(self) -> None:
        """A 2px-tall column must not draw a 4px corner and spill out of itself."""
        path = charts.column_path(0, 0, 24, 2, rounded=True)
        assert "A2,2" in path


@pytest.mark.unit
class TestBarList:
    def test_rows_scale_against_the_largest_value(self) -> None:
        rows = charts.bar_list([("a", 10), ("b", 5)])
        assert [r.percent for r in rows] == [100.0, 50.0]

    def test_a_tiny_non_zero_value_stays_visible(self) -> None:
        rows = charts.bar_list([("a", 1000), ("b", 1)])
        assert rows[1].percent > 0

    def test_zero_stays_zero(self) -> None:
        assert charts.bar_list([("a", 3), ("b", 0)])[1].percent == 0.0

    def test_optional_sublabel_and_link(self) -> None:
        row = charts.bar_list([("SF-0001", 3, "Repeated failures", None)])[0]
        assert row.sublabel == "Repeated failures"
        assert row.href is None


@pytest.mark.unit
class TestTrend:
    def _points(self) -> list[tuple[datetime, Severity]]:
        return [
            (T0, Severity.MEDIUM),
            (T0 + timedelta(minutes=2), Severity.HIGH),
            (T0 + timedelta(minutes=2, seconds=10), Severity.LOW),
            (T0 + timedelta(minutes=6), Severity.CRITICAL),
        ]

    def test_no_points_is_an_empty_chart_not_an_error(self) -> None:
        assert charts.trend_chart([]).is_empty

    @pytest.mark.parametrize(
        ("span", "expected"),
        [
            (timedelta(minutes=10), timedelta(minutes=1)),
            (timedelta(hours=3), timedelta(minutes=10)),
            (timedelta(days=2), timedelta(hours=2)),
            (timedelta(days=90), timedelta(days=7)),
        ],
    )
    def test_the_bucket_keeps_the_column_count_readable(
        self, span: timedelta, expected: timedelta
    ) -> None:
        assert charts.choose_step(span) == expected

    @pytest.mark.parametrize(
        ("value", "ceiling"), [(0, 1), (1, 1), (3, 5), (7, 10), (18, 20), (51, 100)]
    )
    def test_axis_maximum_rounds_to_a_clean_number(self, value: int, ceiling: int) -> None:
        assert charts.nice_ceiling(value) == ceiling

    def test_every_alert_lands_in_exactly_one_column(self) -> None:
        chart = charts.trend_chart(self._points())
        assert sum(c.total for c in chart.columns) == 4

    def test_high_and_critical_carry_the_emphasis(self) -> None:
        chart = charts.trend_chart(self._points())
        assert sum(c.emphasis for c in chart.columns) == 2
        assert sum(c.other for c in chart.columns) == 2

    def test_columns_never_exceed_24px(self) -> None:
        chart = charts.trend_chart([(T0, Severity.LOW)])
        assert all(c.width <= charts.MAX_COLUMN_WIDTH for c in chart.columns)

    def test_a_short_burst_is_centred_rather_than_a_wall(self) -> None:
        chart = charts.trend_chart([(T0, Severity.LOW)])
        assert len(chart.columns) >= charts.MIN_BUCKETS

    def test_emphasis_sits_on_the_baseline(self) -> None:
        """Where it is easiest to compare across columns."""
        chart = charts.trend_chart([(T0, Severity.HIGH), (T0, Severity.LOW)])
        stacked = next(c for c in chart.columns if c.total == 2)
        assert [s.series for s in stacked.segments] == ["emphasis", "other"]

    def test_only_the_top_of_a_stack_is_rounded(self) -> None:
        chart = charts.trend_chart([(T0, Severity.HIGH), (T0, Severity.LOW)])
        lower, upper = next(c for c in chart.columns if c.total == 2).segments
        assert "A" not in lower.path
        assert "A" in upper.path

    def test_axis_ticks_are_whole_alerts(self) -> None:
        chart = charts.trend_chart(self._points())
        assert all(isinstance(value, int) for _, value in chart.y_ticks)
        assert chart.y_ticks[0][1] == 0

    def test_one_direct_label_on_the_peak(self) -> None:
        chart = charts.trend_chart(self._points())
        assert chart.peak is not None
        assert chart.peak.total == max(c.total for c in chart.columns)


@pytest.mark.unit
class TestSeverityTrack:
    def _verdict(self, *points: int) -> AlertSeverity:
        return AlertSeverity.from_factors(
            [
                SeverityFactor(name=f"factor_{i}", points=p, detail="applied")
                for i, p in enumerate(points)
            ]
        )

    def test_each_positive_factor_becomes_a_segment(self) -> None:
        track = charts.severity_track(self._verdict(65, 5, 15))
        assert [s.points for s in track.positive] == [65, 5, 15]

    def test_the_score_marker_sits_at_the_score(self) -> None:
        track = charts.severity_track(self._verdict(40))
        assert track.score_x == pytest.approx(track.track_x + 0.4 * track.track_width)

    def test_deductions_are_drawn_back_from_the_positive_total(self) -> None:
        track = charts.severity_track(self._verdict(65, -10))
        assert len(track.deductions) == 1
        assert track.deductions[0].x == pytest.approx(track.track_x + 0.55 * track.track_width)

    def test_overflow_is_marked_as_clamped_not_hidden(self) -> None:
        track = charts.severity_track(self._verdict(85, 20, 15))
        assert track.clamped is True
        assert track.score == 100

    def test_band_edges_match_the_severity_thresholds(self) -> None:
        track = charts.severity_track(self._verdict(30))
        unit = track.track_width / 100
        assert track.band_edges == [
            pytest.approx(track.track_x + edge * unit) for edge in (30, 60, 85)
        ]


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestFormatting:
    @pytest.mark.parametrize(
        ("value", "text"), [(9, "9"), (1284, "1,284"), (12_900, "12.9K"), (4_200_000, "4.2M")]
    )
    def test_compact_figures(self, value: int, text: str) -> None:
        assert compact(value) == text

    def test_relative_time(self) -> None:
        assert ago(T0, now=T0 + timedelta(hours=3)) == "3h ago"
        assert ago(T0, now=T0 + timedelta(seconds=5)) == "5s ago"
        assert ago(None) == "-"

    def test_json_and_names(self) -> None:
        assert pretty_json({"b": 1, "a": 2}).index('"a"') < pretty_json({"b": 1, "a": 2}).index(
            '"b"'
        )
        assert humanise("privileged_account") == "Privileged account"

    def test_no_filter_marks_its_output_safe(self) -> None:
        """A filter returning Markup would bypass autoescaping for whatever
        attacker-controlled value passed through it."""
        hostile = "<script>alert(1)</script>"
        for name, function in FILTERS.items():
            try:
                result = function(hostile)  # type: ignore[operator]
            except (TypeError, AttributeError, ValueError):
                continue
            assert not isinstance(result, Markup), f"filter {name} returns Markup"


# ---------------------------------------------------------------------------
# The CSP contract, checked against the source tree
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestNothingInlineAnywhere:
    def _templates(self) -> list[Path]:
        found = sorted(TEMPLATE_DIR.glob("*.html"))
        assert found, "no templates found"
        return found

    def test_autoescaping_is_on(self) -> None:
        assert templates.env.autoescape is True

    def test_no_template_carries_inline_style(self) -> None:
        for path in self._templates():
            text = path.read_text(encoding="utf-8")
            assert "<style" not in text, f"{path.name} has a <style> block"
            assert not re.search(r"\sstyle\s*=", text), f"{path.name} has a style attribute"

    def test_no_template_carries_inline_script(self) -> None:
        for path in self._templates():
            text = path.read_text(encoding="utf-8")
            for tag in re.findall(r"<script\b[^>]*>", text):
                assert "src=" in tag, f"{path.name} has an inline <script>"
            # Only inside HTML tags: "{% set only = ... %}" is Jinja, not markup.
            for tag in re.findall(r"<[a-zA-Z][^>]*>", text):
                assert not re.search(r"\son[a-z]+\s*=", tag), (
                    f"{path.name} has an event-handler attribute: {tag[:60]}"
                )
            assert "javascript:" not in text.lower(), f"{path.name} has a javascript: URL"

    def test_no_template_marks_anything_safe(self) -> None:
        for path in self._templates():
            text = path.read_text(encoding="utf-8")
            assert "|safe" not in text.replace(" ", ""), f"{path.name} uses |safe"
            assert "autoescape false" not in text, f"{path.name} disables autoescaping"

    def test_the_script_never_parses_html(self) -> None:
        """Tooltip text can be attacker-controlled; it goes in as text only."""
        code = (STATIC_DIR / "console.js").read_text(encoding="utf-8")
        for sink in (
            r"\.innerHTML\s*=",
            r"\.outerHTML\s*=",
            r"insertAdjacentHTML",
            r"document\.write",
            r"\beval\(",
            r"new Function\(",
        ):
            assert not re.search(sink, code), f"console.js uses {sink}"
        assert "textContent" in code

    def test_no_external_origins_are_referenced(self) -> None:
        """The CSP allows 'self' only; a remote font or CDN would silently fail."""
        for path in [*self._templates(), STATIC_DIR / "console.css"]:
            text = path.read_text(encoding="utf-8")
            for url in re.findall(
                r"(?:src|href)\s*=\s*\"(https?://[^\"]+)\"|url\((https?://[^)]+)\)", text
            ):
                target = url[0] or url[1]
                # Outbound documentation links to ATT&CK are navigation, not
                # resources the page loads; they are rendered from the catalogue.
                assert False, f"{path.name} loads a remote resource: {target}"


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
@pytest.mark.integration
class TestPages:
    def test_an_empty_database_shows_guidance_not_an_error(self, client: TestClient) -> None:
        response = client.get("/")
        assert response.status_code == 200
        assert "Nothing to triage in this window" in response.text
        assert "sentinelflow demo" in response.text

    def test_every_page_renders(self, demo: Settings, client: TestClient) -> None:
        alert_id = _first_alert_id(demo)
        with session_scope(demo) as session:
            incident_id = repository.list_incidents(session, limit=1)[0].incident_id
        for path in (
            "/",
            "/?range=24h",
            "/alerts",
            "/alerts?open=true",
            f"/alerts/{alert_id}",
            "/incidents",
            f"/incidents/{incident_id}",
            "/rules",
        ):
            response = client.get(path)
            assert response.status_code == 200, path
            assert response.headers["content-type"].startswith("text/html")

    def test_every_html_response_carries_the_csp(self, demo: Settings, client: TestClient) -> None:
        for path in ("/", "/alerts", "/rules", "/alerts/not-a-uuid"):
            policy = client.get(path).headers.get("content-security-policy", "")
            assert "script-src 'self'" in policy
            assert "style-src 'self'" in policy

    def test_rendered_pages_carry_nothing_the_csp_would_block(
        self, demo: Settings, client: TestClient
    ) -> None:
        """The contract that matters is the HTML the browser receives."""
        alert_id = _first_alert_id(demo)
        for path in ("/", "/alerts", f"/alerts/{alert_id}", "/incidents", "/rules"):
            html = client.get(path).text
            assert "<style" not in html, path
            for tag in re.findall(r"<[a-zA-Z][^>]*>", html):
                assert not re.search(r"\sstyle\s*=", tag), f"{path}: {tag[:80]}"
                assert not re.search(r"\son[a-z]+\s*=", tag), f"{path}: {tag[:80]}"
            for tag in re.findall(r"<script\b[^>]*>", html):
                assert "src=" in tag, f"{path} has inline script"

    def test_static_assets_are_served(self, client: TestClient) -> None:
        for path in ("/static/console.css", "/static/console.js", "/static/favicon.svg"):
            assert client.get(path).status_code == 200

    @pytest.mark.parametrize(
        "path",
        ["/alerts/not-a-uuid", "/alerts/00000000-0000-0000-0000-000000000000", "/incidents/nope"],
    )
    def test_unknown_records_get_an_html_404(self, client: TestClient, path: str) -> None:
        response = client.get(path)
        assert response.status_code == 404
        assert "text/html" in response.headers["content-type"]
        assert "No such" in response.text

    def test_an_unknown_range_falls_back_rather_than_erroring(
        self, demo: Settings, client: TestClient
    ) -> None:
        assert client.get("/?range=bogus").status_code == 200
        assert resolve_range("bogus") == "all"

    def test_unknown_queue_filters_are_ignored(self, demo: Settings, client: TestClient) -> None:
        assert client.get("/alerts?severity=apocalyptic&status=weird").status_code == 200

    def test_the_overview_shows_the_headline_figures(
        self, demo: Settings, client: TestClient
    ) -> None:
        html = client.get("/").text
        assert "Open alerts" in html
        assert "When the serious activity happened" in html
        assert "seg--emphasis" in html
        assert "Table view" in html

    def test_the_headline_counts_agree_with_their_nouns(
        self, demo: Settings, client: TestClient
    ) -> None:
        """Stage 17: it said "1 potential investigations", and went on calling an
        investigation potential after an analyst had confirmed it."""
        html = " ".join(client.get("/").text.split())
        assert "1 investigation" in html
        assert "investigations" not in html.split("raised by deterministic rules", 1)[1][:40]
        assert "potential investigation" not in html

    def test_a_single_host_is_a_stat_not_a_one_bar_chart(
        self, demo: Settings, client: TestClient
    ) -> None:
        html = client.get("/").text
        assert "all on" in html
        assert 'class="solo"' in html

    def test_the_attack_strip_names_the_gaps(self, demo: Settings, client: TestClient) -> None:
        html = client.get("/").text
        assert "not observed" in html
        assert "T1110" in html


@pytest.mark.integration
class TestStrataOfTrust:
    def test_the_four_layers_appear_in_order(self, demo: Settings, client: TestClient) -> None:
        html = client.get(f"/alerts/{_first_alert_id(demo)}").text
        positions = [
            html.index(name) for name in ("Observed", "Determined", "Suggested", "Decided")
        ]
        assert positions == sorted(positions)

    def test_the_severity_shows_its_working(self, demo: Settings, client: TestClient) -> None:
        html = client.get(f"/alerts/{_first_alert_id(demo)}").text
        assert "How the severity was calculated" in html
        assert "rule_severity" in html
        assert "method: deterministic" in html

    def test_with_ai_off_the_suggested_layer_says_so(
        self, demo: Settings, client: TestClient
    ) -> None:
        html = client.get(f"/alerts/{_first_alert_id(demo)}").text
        assert "AI is off" in html

    def test_ai_output_is_labelled_and_kept_beside_the_verdict(
        self, demo: Settings, client: TestClient
    ) -> None:
        alert_id = _first_alert_id(demo)
        with session_scope(demo) as session:
            alert = repository.get_alert(session, __import__("uuid").UUID(alert_id))
            assert alert is not None
            repository.save_ai_analysis(
                session,
                AIAnalysis(
                    alert_id=alert.alert_id,
                    provider="ollama",
                    model="llama3.1:8b",
                    summary="An advisory reading of the evidence.",
                    statements=[
                        AIStatement(
                            statement_type=StatementType.UNKNOWN, text="Whether it was authorised."
                        )
                    ],
                    suggested_severity=Severity.LOW,
                    injection_suspected=True,
                ),
            )
            deterministic = alert.severity_level.value
        html = client.get(f"/alerts/{alert_id}").text
        assert "AI suggestion · not authoritative" in html
        assert "NOT AUTHORITATIVE" in html
        assert "Deterministic severity" in html
        assert "Possible prompt injection" in html
        # The model's opinion is shown beside the verdict and changes nothing.
        with session_scope(demo) as session:
            stored = repository.get_alert(session, __import__("uuid").UUID(alert_id))
            assert stored is not None and stored.severity_level.value == deterministic

    def test_an_incident_is_presented_as_potential(
        self, demo: Settings, client: TestClient
    ) -> None:
        with session_scope(demo) as session:
            incident_id = repository.list_incidents(session, limit=1)[0].incident_id
        html = client.get(f"/incidents/{incident_id}").text
        assert "Potential incident." in html
        assert "No compromise is asserted" in html
        assert "Timeline" in html


# ---------------------------------------------------------------------------
# Hostile content
# ---------------------------------------------------------------------------
@pytest.mark.integration
class TestHostileEventData:
    PAYLOAD = "<script>alert('xss')</script>"
    ATTR_PAYLOAD = '"><img src=x onerror=alert(1)>'

    @pytest.fixture
    def hostile(self, console_settings: Settings) -> Settings:
        event = SecurityEvent(
            timestamp=T0,
            source="canonical",
            event_type="process_creation",
            hostname=self.PAYLOAD,
            username=self.ATTR_PAYLOAD,
            process_name="powershell.exe",
            parent_process="cmd.exe",
            command_line=f"powershell.exe -enc {'A' * 24} {self.ATTR_PAYLOAD}",
            raw_event={"note": self.PAYLOAD},
        )
        _run_pipeline(console_settings, [event])
        return console_settings

    def test_the_payload_reached_an_alert(self, hostile: Settings) -> None:
        with session_scope(hostile) as session:
            assert repository.count_alerts(session) >= 1

    @pytest.mark.parametrize("page", ["/", "/alerts", "detail"])
    def test_event_fields_render_as_text_not_markup(
        self, hostile: Settings, client: TestClient, page: str
    ) -> None:
        path = f"/alerts/{_first_alert_id(hostile)}" if page == "detail" else page
        html = client.get(path).text
        assert self.PAYLOAD not in html
        assert "<img src=x onerror" not in html
        assert "&lt;script&gt;" in html

    def test_hostile_text_cannot_break_out_of_an_attribute(
        self, hostile: Settings, client: TestClient
    ) -> None:
        html = client.get(f"/alerts/{_first_alert_id(hostile)}").text
        assert '"><img' not in html
        assert "&#34;&gt;&lt;img" in html or "&quot;&gt;&lt;img" in html


# ---------------------------------------------------------------------------
# One builder, two consumers
# ---------------------------------------------------------------------------
@pytest.mark.integration
class TestSharedStatistics:
    def test_top_rules_is_populated(self, demo: Settings, client: TestClient) -> None:
        """/api/v1/stats used to return an empty top_rules."""
        stats = client.get("/api/v1/stats").json()
        assert stats["top_rules"]
        assert "SF-0003" in stats["top_rules"]

    def test_the_api_and_the_dashboard_agree(self, demo: Settings, client: TestClient) -> None:
        api = client.get("/api/v1/stats").json()
        with session_scope(demo) as session:
            page = collect_dashboard_stats(session)
        assert api["alerts"] == page.alerts_total
        assert api["alerts_open"] == page.alerts_open
        assert api["severity_counts"] == page.severity_counts

    def test_windows_filter_on_event_time(self, console_settings: Settings) -> None:
        """A week-old export imported today is not 'last 24 hours' activity."""
        old = get_adapter("canonical").normalise(
            {
                "timestamp": (datetime.now(UTC) - timedelta(days=10)).isoformat(),
                "source": "canonical",
                "event_type": "log_cleared",
                "hostname": "OLD-HOST",
            }
        )
        _run_pipeline(console_settings, [old])
        with session_scope(console_settings) as session:
            day = collect_dashboard_stats(session, range_key="24h")
            forever = collect_dashboard_stats(session, range_key="all")
        assert day.alerts_total == 0
        assert forever.alerts_total == 1
