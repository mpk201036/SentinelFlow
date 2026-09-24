"""Requesting, checking and storing an advisory analysis of one alert.

The sequence for one request:

1. Load the alert and its primary event. Build the evidence document.
2. Scan the evidence for text aimed at a model.
3. Build the prompt: fixed rules, nonce-delimited evidence, and a warning if
   step 2 found anything.
4. Ask the provider. Failure here means "no analysis", never an exception
   into the caller's workflow.
5. Parse the reply against the schema. Unusable output is rejected whole.
6. Ground the reply: downgrade unsupported observed claims and note any
   ATT&CK technique the alert is not mapped to.
7. Store the analysis in ``ai_analysis`` and write two audit entries.

What the service does not do is as important. It never writes to the alert:
not its severity, status, classification, tags or mappings. The only table it
writes besides ``ai_analysis`` and ``ai_statements`` is the audit log.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.ai.evidence import build_evidence
from app.ai.grounding import ground
from app.ai.injection import InjectionSignal, scan_evidence
from app.ai.output import AIOutputError, parse_reply
from app.ai.prompts import PROMPT_VERSION, build_prompt
from app.ai.providers import ModelProvider, ProviderError
from app.core.logging import get_logger
from app.database import repository
from app.models.ai import MAX_LIST_ENTRIES, AIAnalysis
from app.models.alert import Alert
from app.models.analyst import AuditEntry
from app.models.enums import Actor, AuditAction

logger = get_logger(__name__)


class OutcomeKind(StrEnum):
    STORED = "stored"
    DISABLED = "disabled"
    UNAVAILABLE = "unavailable"
    REJECTED = "rejected"


class AlertNotFoundError(LookupError):
    """No alert has the requested id."""


@dataclass(frozen=True)
class AnalysisOutcome:
    """What happened. Only ``STORED`` carries an analysis."""

    kind: OutcomeKind
    alert_id: UUID
    analysis: AIAnalysis | None = None
    problem: str | None = None
    injection_signals: tuple[InjectionSignal, ...] = field(default_factory=tuple)

    @property
    def stored(self) -> bool:
        return self.kind is OutcomeKind.STORED


class AIAnalysisService:
    """Produces advisory analyses. Holds no state between requests."""

    def __init__(
        self,
        session: Session,
        provider: ModelProvider | None,
        *,
        requested_by: str | None = None,
        actor: Actor = Actor.ANALYST,
    ) -> None:
        self.session = session
        self.provider = provider
        self.requested_by = requested_by
        self.actor = actor

    def analyze_alert(self, alert_id: UUID) -> AnalysisOutcome:
        alert = repository.get_alert(self.session, alert_id)
        if alert is None:
            raise AlertNotFoundError(str(alert_id))
        if self.provider is None:
            return AnalysisOutcome(
                OutcomeKind.DISABLED, alert_id, problem="AI is disabled in the configuration"
            )

        event = repository.get_event(self.session, alert.primary_event_id)
        evidence = build_evidence(alert, event)
        signals = tuple(scan_evidence(evidence))
        prompt = build_prompt(evidence, injection_signals=signals)

        try:
            reply = self.provider.complete(prompt)
        except ProviderError as exc:
            return self._fail(alert, OutcomeKind.UNAVAILABLE, str(exc), signals)

        try:
            parsed = parse_reply(reply.content)
        except AIOutputError as exc:
            return self._fail(alert, OutcomeKind.REJECTED, str(exc), signals)

        grounding = ground(
            parsed.statements,
            evidence,
            other_text=[
                parsed.summary,
                *parsed.suspicious_observations,
                *parsed.possible_explanations,
                *parsed.analyst_questions,
                *parsed.recommended_next_steps,
                parsed.suggested_severity_rationale or "",
            ],
        )
        notes = [*parsed.notes, *grounding.notes]
        if evidence.clipped:
            notes.append(
                f"{len(evidence.clipped)} long value(s) were clipped before the model saw them, "
                f"starting with {evidence.clipped[0]}."
            )
        if (
            signals
            and parsed.suggested_severity is not None
            and parsed.suggested_severity < alert.severity_level
        ):
            notes.append(
                "The model suggests a lower severity than SentinelFlow, and the evidence "
                "contains text aimed at a model. The lower suggestion may have been steered."
            )

        try:
            analysis = AIAnalysis(
                alert_id=alert.alert_id,
                provider=self.provider.name,
                model=reply.model,
                duration_ms=reply.duration_ms,
                prompt_version=PROMPT_VERSION,
                summary=parsed.summary,
                statements=grounding.statements,
                suspicious_observations=parsed.suspicious_observations,
                possible_explanations=parsed.possible_explanations,
                analyst_questions=parsed.analyst_questions,
                recommended_next_steps=parsed.recommended_next_steps,
                suggested_severity=parsed.suggested_severity,
                suggested_severity_rationale=parsed.suggested_severity_rationale,
                injection_suspected=bool(signals),
                injection_signals=[str(signal) for signal in signals][:MAX_LIST_ENTRIES],
                grounding_notes=notes[:MAX_LIST_ENTRIES],
                truncated=parsed.truncated,
            )
        except ValidationError as exc:
            return self._fail(
                alert,
                OutcomeKind.REJECTED,
                f"the reply could not be stored ({exc.error_count()} validation error(s))",
                signals,
            )

        repository.save_ai_analysis(self.session, analysis)
        self._audit_request(alert, analysis.model, "stored", signals)
        repository.record_audit(
            self.session,
            AuditEntry(
                actor=Actor.AI_ASSISTANT,
                actor_name=f"{analysis.provider}/{analysis.model}"[:128],
                action=AuditAction.AI_ANALYSIS_STORED,
                object_type="alert",
                object_id=alert.alert_id,
                after=f"analysis {analysis.analysis_id}",
                detail=(
                    f"prompt={PROMPT_VERSION} statements={len(analysis.statements)} "
                    f"downgraded={grounding.downgraded} notes={len(analysis.grounding_notes)} "
                    f"suggested={analysis.suggested_severity.value if analysis.suggested_severity else '-'} "
                    f"deterministic={alert.severity_level.value} (unchanged)"
                ),
            ),
        )
        logger.info(
            "stored AI analysis %s for alert %s (%s ms, injection=%s)",
            analysis.analysis_id,
            alert.alert_id,
            analysis.duration_ms,
            analysis.injection_suspected,
        )
        return AnalysisOutcome(
            OutcomeKind.STORED, alert.alert_id, analysis=analysis, injection_signals=signals
        )

    # ------------------------------------------------------------------
    def _fail(
        self,
        alert: Alert,
        kind: OutcomeKind,
        problem: str,
        signals: tuple[InjectionSignal, ...],
    ) -> AnalysisOutcome:
        model = self.provider.model if self.provider is not None else "-"
        self._audit_request(alert, model, f"{kind.value}: {problem}", signals)
        logger.warning("AI analysis of alert %s %s: %s", alert.alert_id, kind.value, problem)
        return AnalysisOutcome(kind, alert.alert_id, problem=problem, injection_signals=signals)

    def _audit_request(
        self, alert: Alert, model: str, outcome: str, signals: tuple[InjectionSignal, ...]
    ) -> None:
        provider = self.provider.name if self.provider is not None else "-"
        repository.record_audit(
            self.session,
            AuditEntry(
                actor=self.actor,
                actor_name=self.requested_by,
                action=AuditAction.AI_ANALYSIS_REQUESTED,
                object_type="alert",
                object_id=alert.alert_id,
                detail=(
                    f"provider={provider} model={model} prompt={PROMPT_VERSION} "
                    f"injection_signals={len(signals)} outcome={outcome}"
                )[:1024],
            ),
        )
