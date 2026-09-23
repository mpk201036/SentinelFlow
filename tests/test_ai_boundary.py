"""Stage 2 — the AI trust boundary.

These are the most important tests in the project. They do not check that the
AI is clever; they check that the system stays correct when it is not. Each one
corresponds to a claim made in the README, so if a future change breaks the
separation, the claim fails with it.
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.models import (
    AIAnalysis,
    AIStatement,
    Alert,
    AlertSeverity,
    Severity,
    SeverityFactor,
    StatementType,
)

pytestmark = pytest.mark.unit


def make_analysis(**overrides: object) -> AIAnalysis:
    payload: dict[str, object] = {
        "alert_id": uuid4(),
        "provider": "ollama",
        "model": "llama3.1:8b",
        "summary": "PowerShell executed on WIN-LAB-01 shortly after a successful logon.",
    }
    payload.update(overrides)
    return AIAnalysis(**payload)  # type: ignore[arg-type]


def make_alert(score: int = 65) -> Alert:
    return Alert(
        title="Encoded PowerShell on WIN-LAB-01",
        primary_event_id=uuid4(),
        severity=AlertSeverity.from_factors(
            [SeverityFactor(name="rule", points=score, detail="Rule SF-0003 is HIGH severity")]
        ),
    )


class TestTheAiCannotOwnASeverity:
    def test_ai_analysis_has_no_field_called_severity(self) -> None:
        """Only `suggested_severity` exists, so the two can never be confused."""
        assert "severity" not in AIAnalysis.model_fields
        assert "suggested_severity" in AIAnalysis.model_fields

    def test_the_alert_verdict_will_not_accept_a_bare_severity(self) -> None:
        """`suggested_severity` is a Severity; `Alert.severity` is an AlertSeverity."""
        analysis = make_analysis(suggested_severity=Severity.CRITICAL)
        alert = make_alert()
        with pytest.raises(ValidationError):
            alert.severity = analysis.suggested_severity  # type: ignore[assignment]

    def test_an_ai_opinion_does_not_move_the_deterministic_verdict(self) -> None:
        alert = make_alert(score=65)
        analysis = make_analysis(
            alert_id=alert.alert_id,
            suggested_severity=Severity.CRITICAL,
            suggested_severity_rationale="Encoded commands are usually malicious.",
        )
        assert analysis.suggested_severity is Severity.CRITICAL
        assert alert.severity_level is Severity.HIGH
        assert alert.severity.method == "deterministic"

    def test_the_alert_model_holds_no_reference_to_ai_output(self) -> None:
        """AI output is a leaf node: it reads from the pipeline and writes only to itself."""
        for name, field in Alert.model_fields.items():
            assert name.split("_")[0] != "ai", f"Alert.{name} looks like an AI field"
            assert "AIAnalysis" not in str(field.annotation)


class TestTheAdvisoryLabelIsNotOptional:
    def test_is_advisory_defaults_to_true(self) -> None:
        assert make_analysis().is_advisory is True

    def test_is_advisory_cannot_be_turned_off(self) -> None:
        with pytest.raises(ValidationError):
            make_analysis(is_advisory=False)

    def test_the_label_survives_serialisation(self) -> None:
        """There must be no path to the database, API or report that drops it."""
        payload = json.loads(make_analysis().to_json())
        assert payload["is_advisory"] is True

    def test_a_disclaimer_is_available_for_display(self) -> None:
        assert "NOT AUTHORITATIVE" in AIAnalysis.DISCLAIMER


class TestProvenanceIsMandatory:
    @pytest.mark.parametrize("missing", ["provider", "model"])
    def test_provider_and_model_must_be_recorded(self, missing: str) -> None:
        payload = {
            "alert_id": uuid4(),
            "provider": "ollama",
            "model": "llama3.1:8b",
            "summary": "x y z",
        }
        payload.pop(missing)
        with pytest.raises(ValidationError):
            AIAnalysis(**payload)  # type: ignore[arg-type]

    def test_blank_provenance_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="which provider and model"):
            make_analysis(provider="   ")

    def test_analysis_records_when_it_was_generated(self) -> None:
        assert make_analysis().generated_at.tzinfo is not None


class TestStatementsMustBeLabelled:
    def test_every_statement_carries_an_epistemic_label(self) -> None:
        analysis = make_analysis(
            statements=[
                {"statement_type": "observed", "text": "powershell.exe was spawned by cmd.exe."},
                {"statement_type": "inferred", "text": "This may be an interactive admin session."},
                {"statement_type": "unknown", "text": "Whether the activity was authorised."},
            ]
        )
        assert [s.statement_type for s in analysis.statements] == [
            StatementType.OBSERVED,
            StatementType.INFERRED,
            StatementType.UNKNOWN,
        ]

    def test_an_unlabelled_statement_is_rejected(self) -> None:
        """A model that states a guess as fact produces invalid output, not UI text."""
        with pytest.raises(ValidationError):
            make_analysis(statements=[{"text": "The host is compromised."}])

    def test_an_invented_label_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            make_analysis(statements=[{"statement_type": "certain", "text": "Compromised."}])

    def test_empty_statements_are_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AIStatement(statement_type=StatementType.OBSERVED, text="   ")

    def test_statements_are_filterable_by_label(self) -> None:
        analysis = make_analysis(
            statements=[
                {"statement_type": "observed", "text": "PowerShell executed on WIN-LAB-01."},
                {"statement_type": "observed", "text": "The parent process was cmd.exe."},
                {"statement_type": "unknown", "text": "Whether the user initiated it."},
            ]
        )
        assert len(analysis.observed) == 2
        assert len(analysis.inferred) == 0
        assert len(analysis.unknown) == 1

    def test_statement_renders_with_its_label(self) -> None:
        statement = AIStatement(
            statement_type=StatementType.INFERRED, text="Possibly benign admin work."
        )
        assert str(statement) == "INFERRED: Possibly benign admin work."


class TestOverconfidenceIsDetectable:
    def test_analysis_without_unknowns_is_flagged(self) -> None:
        """There is always something the logs do not say."""
        analysis = make_analysis(
            statements=[{"statement_type": "observed", "text": "PowerShell executed."}]
        )
        assert analysis.has_unsupported_confidence is True

    def test_analysis_that_admits_gaps_is_not_flagged(self) -> None:
        analysis = make_analysis(
            statements=[
                {"statement_type": "observed", "text": "PowerShell executed."},
                {"statement_type": "unknown", "text": "Whether it was authorised."},
            ]
        )
        assert analysis.has_unsupported_confidence is False

    def test_an_empty_analysis_is_not_flagged(self) -> None:
        assert make_analysis().has_unsupported_confidence is False


class TestHostileInputHandling:
    def test_injection_is_recorded_rather_than_assumed_away(self) -> None:
        analysis = make_analysis(injection_suspected=True)
        assert analysis.injection_suspected is True
        assert json.loads(analysis.to_json())["injection_suspected"] is True

    def test_injection_defaults_to_false(self) -> None:
        assert make_analysis().injection_suspected is False

    def test_model_output_is_capped_and_the_capping_is_recorded(self) -> None:
        """A local model can loop. That must truncate visibly, not fill the database."""
        analysis = make_analysis(analyst_questions=[f"question {i}" for i in range(500)])
        assert len(analysis.analyst_questions) == 20
        assert analysis.truncated is True

    def test_normal_output_is_not_marked_truncated(self) -> None:
        assert make_analysis(analyst_questions=["one", "two"]).truncated is False

    def test_statement_list_is_capped_too(self) -> None:
        analysis = make_analysis(
            statements=[{"statement_type": "observed", "text": f"line {i}"} for i in range(100)]
        )
        assert len(analysis.statements) == 40
        assert analysis.truncated is True

    def test_control_characters_in_model_output_are_stripped(self) -> None:
        analysis = make_analysis(summary="Suspicious\x00 activity‮ observed on the host.")
        assert "\x00" not in analysis.summary
        assert "‮" not in analysis.summary

    def test_analysis_records_truncation_visibly(self) -> None:
        assert make_analysis(truncated=True).truncated is True


class TestAiOutputIsImmutable:
    def test_analysis_cannot_be_edited_after_generation(self) -> None:
        analysis = make_analysis()
        with pytest.raises(ValidationError):
            analysis.summary = "Something else."  # type: ignore[misc]

    def test_round_trip_is_lossless(self) -> None:
        analysis = make_analysis(
            statements=[{"statement_type": "observed", "text": "PowerShell executed."}],
            suggested_severity=Severity.MEDIUM,
        )
        assert AIAnalysis.model_validate_json(analysis.to_json()) == analysis
