"""Services: the deterministic pipeline and the context it runs in.

context     what this estate considers critical or privileged
severity    additive, explainable scoring
alerting    assembling alerts an analyst can queue
pipeline    the order the stages run in
workflow    the analyst's decisions, their rules, and their audit trail
"""

from app.services.alerting import AlertBuildResult, AlertFactory, build_title, worst_severity
from app.services.context import BusinessHours, EnvironmentContext, get_context, load_context
from app.services.correlation import (
    CorrelationEngine,
    CorrelationGroup,
    CorrelationResult,
    CorrelationService,
    Signal,
    signals_for,
)
from app.services.pipeline import TriagePipeline, TriageResult
from app.services.severity import (
    FACTOR_NAMES,
    REPEAT_WINDOW_HOURS,
    SeverityEngine,
    SeverityWeights,
    describe_scale,
)
from app.services.workflow import (
    UNCHANGED,
    AlertDecision,
    AnalystWorkflow,
    Channel,
    DecisionResult,
    IncidentDecision,
    RecordNotFoundError,
    StaleDecisionError,
    WorkflowError,
)

__all__ = [
    "FACTOR_NAMES",
    "REPEAT_WINDOW_HOURS",
    "UNCHANGED",
    "AlertBuildResult",
    "AlertDecision",
    "AlertFactory",
    "AnalystWorkflow",
    "BusinessHours",
    "Channel",
    "CorrelationEngine",
    "CorrelationGroup",
    "CorrelationResult",
    "CorrelationService",
    "DecisionResult",
    "EnvironmentContext",
    "IncidentDecision",
    "RecordNotFoundError",
    "SeverityEngine",
    "SeverityWeights",
    "Signal",
    "StaleDecisionError",
    "TriagePipeline",
    "TriageResult",
    "WorkflowError",
    "build_title",
    "describe_scale",
    "get_context",
    "load_context",
    "signals_for",
    "worst_severity",
]
