"""Services: the deterministic pipeline and the context it runs in.

context     what this estate considers critical or privileged
severity    additive, explainable scoring
alerting    assembling alerts an analyst can queue
pipeline    the order the stages run in
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
from app.services.pipeline import REPEAT_WINDOW_HOURS, TriagePipeline, TriageResult
from app.services.severity import (
    FACTOR_NAMES,
    SeverityEngine,
    SeverityWeights,
    describe_scale,
)

__all__ = [
    "FACTOR_NAMES",
    "REPEAT_WINDOW_HOURS",
    "AlertBuildResult",
    "AlertFactory",
    "BusinessHours",
    "CorrelationEngine",
    "CorrelationGroup",
    "CorrelationResult",
    "CorrelationService",
    "EnvironmentContext",
    "SeverityEngine",
    "SeverityWeights",
    "Signal",
    "TriagePipeline",
    "TriageResult",
    "build_title",
    "describe_scale",
    "get_context",
    "load_context",
    "signals_for",
    "worst_severity",
]
