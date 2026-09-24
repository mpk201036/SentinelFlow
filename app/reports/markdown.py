"""The Markdown report, and the escaping that makes it safe to share.

A Markdown report is read in places SentinelFlow does not control: GitHub,
GitLab, a ticketing system, a VS Code preview. Most of the text in it came
from an event an attacker may have written, or from a model that read one.
Markdown written carelessly would let that text:

* add a link or an image - ``![](https://collector.example/pixel)`` is a
  tracking pixel that fires when the report is opened;
* inject raw HTML, which many renderers pass through;
* forge structure - a fake "## Analyst conclusion" heading, or a table row;
* break out of a code block by closing its fence early.

Every untrusted string therefore goes through one of three functions:

* :func:`md_text` - prose. Markdown punctuation is escaped, ``<`` and ``>``
  cannot start a tag, line breaks cannot start a new block, and URLs,
  domains and e-mail addresses are defanged so no renderer links them.
* :func:`md_code` - a short value inside inline code, fenced with more
  backticks than the value contains.
* :func:`md_block` - verbatim evidence inside a fenced block whose fence is
  longer than any run of backticks in the content, so nothing inside can
  close it.

The only links in a report are the ones SentinelFlow writes itself: ATT&CK
technique pages from the local catalogue.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from app import __version__
from app.core.display import audit_label, audit_summary, audit_who
from app.enrichment.defang import defang_email, defang_text, defang_url
from app.models.ai import AIAnalysis
from app.models.enums import IndicatorType, StatementType
from app.models.indicator import Indicator
from app.reports.model import AlertSection, Report

#: Characters that can start or shape Markdown inline syntax.
_INLINE_SPECIAL = re.compile(r"([\\`*_\[\]<>|~#!{}])")
#: Constructs that only matter at the start of a line: lists, headings,
#: quotes, thematic breaks and setext underlines.
_LINE_START = re.compile(r"^(\s*)(\d+)([.)])|^(\s*)([-+=>])")
_BACKTICK_RUN = re.compile(r"`+")

AI_DISCLAIMER = AIAnalysis.DISCLAIMER


# ---------------------------------------------------------------------------
# Escaping
# ---------------------------------------------------------------------------
def md_text(value: object, *, defang: bool = True) -> str:
    """Untrusted prose, safe anywhere inline: in a paragraph, a list item or a table cell."""
    text = " ".join(str(value).split())
    if defang:
        text = defang_text(text)
    # "&" is left alone: an entity in CommonMark decodes to text and can never
    # form a tag or a link, so escaping it would only clutter the source.
    text = _INLINE_SPECIAL.sub(r"\\\1", text)
    return _LINE_START.sub(_escape_line_start, text)


def md_code(value: object, *, in_table: bool = False) -> str:
    """An untrusted value as inline code."""
    text = " ".join(str(value).split())
    if not text:
        return ""
    longest = max((len(run) for run in _BACKTICK_RUN.findall(text)), default=0)
    fence = "`" * (longest + 1)
    if text.startswith("`") or text.endswith("`"):
        text = f" {text} "
    if in_table:
        # Inside a GFM table a pipe ends the cell, even within a code span.
        text = text.replace("|", "\\|")
    return f"{fence}{text}{fence}"


def md_block(value: object, *, info: str = "text") -> str:
    """Verbatim untrusted text in a fenced block that nothing inside can close."""
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    longest = max((len(run) for run in _BACKTICK_RUN.findall(text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{info}\n{text}\n{fence}"


def md_quote(value: object) -> str:
    """Multi-line untrusted prose as a block quote, one escaped line at a time."""
    lines = str(value).replace("\r\n", "\n").split("\n")
    return "\n".join(f"> {md_text(line)}" if line.strip() else ">" for line in lines)


def _escape_line_start(match: re.Match[str]) -> str:
    if match.group(2) is not None:
        return f"{match.group(1)}{match.group(2)}\\{match.group(3)}"
    return f"{match.group(4)}\\{match.group(5)}"


def _cell(value: object) -> str:
    return md_text(value) or " "


def _table(headers: list[str], rows: Iterable[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines)


def indicator_display(indicator: Indicator) -> str:
    """How an indicator is written in a report: defanged where it could be clicked."""
    value = indicator.value
    kind = indicator.indicator_type
    if kind is IndicatorType.URL:
        return defang_url(value)
    if kind is IndicatorType.EMAIL:
        return defang_email(value)
    if kind is IndicatorType.DOMAIN:
        return value.replace(".", "[.]")
    return value


def indicator_scope(indicator: Indicator) -> str:
    if indicator.is_internal:
        return "internal"
    if indicator.is_documentation:
        return "documentation range"
    return "external"


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def render_markdown(report: Report) -> str:
    out: list[str] = []
    add = out.append
    subject = "Investigation" if report.kind == "incident" else "Alert"

    add(f"# {subject} report: {md_text(report.title)}")
    add("")
    add(
        f"**{md_text(report.state_label)}** · deterministic severity "
        f"**{report.severity.value} ({report.top_score}/100)** · "
        f"{len(report.alerts)} alert{'s' if len(report.alerts) != 1 else ''}"
    )
    add("")
    window = report.window
    facts = [
        ["Report ID", md_code(report.report_id, in_table=True)],
        [
            "Generated",
            f"{report.generated_at:%Y-%m-%d %H:%M} UTC by {_cell(report.generated_by)}",
        ],
        [subject, md_code(report.subject_id, in_table=True)],
        ["State", _cell(report.state_label)],
        ["Assigned to", _cell(report.assigned_to or "Unassigned")],
        ["Hosts", ", ".join(md_code(h, in_table=True) for h in report.hostnames) or "-"],
        ["Accounts", ", ".join(md_code(u, in_table=True) for u in report.usernames) or "-"],
    ]
    if window:
        facts.append(
            ["Event window", f"{window[0]:%Y-%m-%d %H:%M:%S} to {window[1]:%Y-%m-%d %H:%M:%S} UTC"]
        )
    add(_table(["", ""], facts))
    add("")
    add(
        "> **Reading this report.** Each section says where its content came from. "
        "*Observed* sections quote the logs. *Deterministic* sections were produced by "
        "rules and are reproducible. The *AI suggestion* section is advisory model output "
        "that influenced nothing else here. *Decided* sections record what an analyst "
        "concluded. Links, domains and e-mail addresses from the evidence are defanged."
    )

    sections = _Numbering()
    add("")
    add(f"## {sections.next()}. Summary")
    add("")
    add(" ".join(md_text(sentence) for sentence in report.summary_sentences()))
    add("")
    add(f"**Analyst conclusion.** {md_text(report.conclusion())}")

    if report.kind == "incident":
        add("")
        add(f"## {sections.next()}. Timeline - observed")
        add("")
        add(
            _table(
                ["Time (UTC)", "Host", "Account", "What happened", "Severity"],
                (
                    [
                        f"{s.event_time:%Y-%m-%d %H:%M:%S}",
                        md_code(s.event.hostname or "-", in_table=True) if s.event else "-",
                        md_code(s.event.username or "-", in_table=True) if s.event else "-",
                        _cell(s.alert.title),
                        f"{s.alert.severity_level.value} {s.alert.severity.score}",
                    ]
                    for s in report.alerts
                ),
            )
        )

    add("")
    add(f"## {sections.next()}. Detections, severity and evidence - deterministic")
    for number, section in enumerate(report.alerts, start=1):
        add("")
        add(_alert_block(section, number, several=len(report.alerts) > 1))

    if report.techniques:
        add("")
        add(f"## {sections.next()}. MITRE ATT&CK - mapped by rule")
        add("")
        add(
            "Each technique was mapped by a detection rule from SentinelFlow's local "
            "catalogue, with the reason recorded. None was suggested by a model."
        )
        add("")
        add(
            _table(
                ["Technique", "Name", "Tactics", "Why it was mapped"],
                (
                    [
                        f"[{use.technique.technique_id}]({use.technique.url})",
                        _cell(use.technique.name),
                        _cell(", ".join(use.technique.tactics)),
                        "<br>".join(md_text(reason) for reason in use.reasons[:3]),
                    ]
                    for use in report.techniques
                ),
            )
        )

    if report.indicators:
        add("")
        add(f"## {sections.next()}. Indicators")
        add("")
        add(
            "Facts about strings that appeared in the evidence, not verdicts. External "
            "indicators come first. URLs, domains and e-mail addresses are defanged."
        )
        add("")
        add(
            _table(
                ["Type", "Value", "Scope", "Seen"],
                (
                    [
                        indicator.indicator_type.value,
                        md_code(indicator_display(indicator), in_table=True),
                        indicator_scope(indicator),
                        str(indicator.occurrences),
                    ]
                    for indicator in report.indicators
                ),
            )
        )

    add("")
    add(f"## {sections.next()}. AI suggestion - advisory, not authoritative")
    add("")
    if not report.analysed_alerts:
        add(
            "No AI analysis was requested for this report's alerts. Nothing above depends "
            "on a model."
        )
    else:
        add(f"> {md_text(AI_DISCLAIMER, defang=False)}")
        for section in report.analysed_alerts:
            add("")
            add(_analysis_block(section))

    add("")
    add(f"## {sections.next()}. Analyst decisions - decided")
    add("")
    add(f"**Conclusion.** {md_text(report.conclusion())}")
    add("")
    add(
        _table(
            ["Alert", "Status", "Classification", "Assigned to"],
            (
                [
                    _cell(s.alert.title),
                    s.alert.status.value,
                    s.alert.classification.value.replace("_", " ")
                    if s.alert.classification
                    else "not classified",
                    _cell(s.alert.assigned_to or "-"),
                ]
                for s in report.alerts
            ),
        )
    )
    notes = report.all_notes
    add("")
    add("### Notes")
    add("")
    if not notes:
        add("No notes were recorded.")
    for attached_to, note in notes:
        add(
            f"**{md_text(note.author)}**, {note.created_at:%Y-%m-%d %H:%M} UTC, on "
            f"{md_text(attached_to)}:"
        )
        add("")
        add(md_quote(note.body))
        add("")

    if report.recommendations:
        add("")
        add(f"## {sections.next()}. Recommended next steps - from the rules")
        add("")
        for number, (rule_id, text) in enumerate(report.recommendations, start=1):
            add(f"{number}. {md_code(rule_id)} {md_text(text)}")

    add("")
    add(f"## {sections.next()}. Audit trail")
    add("")
    add(
        _table(
            ["Time (UTC)", "Who", "What", "Change", "Detail"],
            (
                [
                    f"{entry.occurred_at:%Y-%m-%d %H:%M:%S}",
                    _cell(audit_who(entry)),
                    audit_label(entry.action.value),
                    _cell(audit_summary(entry)),
                    _cell((entry.detail or "")[:300]),
                ]
                for entry in report.history
            ),
        )
    )
    if report.history_truncated:
        add("")
        add(f"Only the first {len(report.history)} entries are included.")

    add("")
    add(f"## {sections.next()}. Scope and limitations")
    add("")
    for line in report.limitations():
        add(f"- {md_text(line, defang=False)}")
    add("")
    add("---")
    add("")
    add(
        f"Generated by SentinelFlow {__version__}. Report {md_code(report.report_id)}: its "
        "SHA-256 is recorded in SentinelFlow's audit trail. Check a copy with "
        "`sentinelflow verify-report <file>`."
    )
    return "\n".join(out).rstrip() + "\n"


def _alert_block(section: AlertSection, number: int, *, several: bool) -> str:
    alert = section.alert
    out: list[str] = []
    add = out.append
    heading = (
        f"### {md_text(alert.title)}" if not several else f"### {number}. {md_text(alert.title)}"
    )
    add(heading)
    add("")
    add(
        f"Severity **{alert.severity_level.value} {alert.severity.score}/100** (deterministic) · "
        f"rule confidence {alert.confidence.value} · alert {md_code(alert.alert_id)}"
    )
    add("")
    add(
        _table(
            ["Factor", "Points", "Why"],
            (
                [md_code(f.name, in_table=True), f"{f.points:+d}", _cell(f.detail)]
                for f in alert.severity.factors
            ),
        )
    )
    for detection in alert.detections:
        add("")
        add(
            f"**{md_code(detection.rule_id)} {md_text(detection.rule_name)}** "
            f"(rule severity {detection.rule_severity.value}). {md_text(detection.description)}"
        )
        for match in detection.matched:
            value = f" -> {md_code(match.observed_value)}" if match.observed_value else ""
            add(f"- {md_code(match.field_name)} {md_text(match.condition)}{value}")
    evidence = section.evidence()
    if evidence:
        add("")
        add("Observed event, verbatim:")
        add("")
        width = max(len(name) for name, _ in evidence)
        add(md_block("\n".join(f"{name.ljust(width)}  {value}" for name, value in evidence)))
    return "\n".join(out)


def _analysis_block(section: AlertSection) -> str:
    analysis = section.latest_analysis
    if analysis is None:
        raise ValueError("only alerts with an analysis get an AI section")
    alert = section.alert
    out: list[str] = []
    add = out.append
    add(f"### {md_text(alert.title)}")
    add("")
    seconds = f"{analysis.duration_ms / 1000:.1f} s · " if analysis.duration_ms else ""
    add(
        f"{md_code(f'{analysis.provider}/{analysis.model}')} · {seconds}prompt "
        f"{md_code(analysis.prompt_version or '-')} · {analysis.generated_at:%Y-%m-%d %H:%M} UTC"
    )
    if analysis.injection_suspected:
        add("")
        add(
            "**Possible prompt injection.** The evidence contained text aimed at a model. "
            "Read this analysis with extra suspicion."
        )
        for signal in analysis.injection_signals:
            add(f"- {md_text(signal)}")
    add("")
    add(f"**Model summary.** {md_text(analysis.summary)}")
    if analysis.suggested_severity is not None:
        add("")
        rationale = (
            f" - {md_text(analysis.suggested_severity_rationale)}"
            if analysis.suggested_severity_rationale
            else ""
        )
        add(
            f"**Suggested severity:** {analysis.suggested_severity.value}{rationale} "
            f"*(SentinelFlow's deterministic severity: {alert.severity_level.value} "
            f"{alert.severity.score}/100, unchanged.)*"
        )
    for kind in (StatementType.OBSERVED, StatementType.INFERRED, StatementType.UNKNOWN):
        statements = analysis.statements_of(kind)
        if not statements:
            continue
        add("")
        add(f"*{kind.value.capitalize()}*")
        add("")
        for statement in statements:
            flag = " *(relabelled from observed by SentinelFlow)*" if statement.downgraded else ""
            add(f"- {md_text(statement.text)}{flag}")
    for heading, items in (
        ("Suspicious observations", analysis.suspicious_observations),
        ("Other explanations", analysis.possible_explanations),
        ("Questions for the analyst", analysis.analyst_questions),
        ("Suggested next steps", analysis.recommended_next_steps),
    ):
        if items:
            add("")
            add(f"*{heading}*")
            add("")
            out.extend(f"- {md_text(item)}" for item in items)
    if analysis.grounding_notes or analysis.truncated:
        add("")
        add("*SentinelFlow checks (not written by the model)*")
        add("")
        out.extend(f"- {md_text(note)}" for note in analysis.grounding_notes)
        if analysis.truncated:
            add("- The model's reply exceeded the size limits and was shortened.")
    return "\n".join(out)


class _Numbering:
    def __init__(self) -> None:
        self.value = 0

    def next(self) -> int:
        self.value += 1
        return self.value
