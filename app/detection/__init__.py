"""Detection: transparent rules evaluated against events.

operators   the condition vocabulary; no rule content is ever executed
schema      the rule definition language, validated at load time
loader      reading rules/*.yaml, reporting what failed instead of failing
engine      evaluation, producing results that show their working
"""

from app.detection.engine import (
    DetectionEngine,
    DetectionRun,
    ThresholdHistory,
    evaluate_condition,
    evaluate_logic,
    resolve_field,
)
from app.detection.loader import (
    RuleError,
    RuleSet,
    load_rule_document,
    load_rule_file,
    load_rules,
    rules_by_technique,
)
from app.detection.operators import OPERATORS, available_operators, shannon_entropy
from app.detection.schema import KNOWN_FIELDS, Condition, Logic, RuleDefinition, Threshold

__all__ = [
    "KNOWN_FIELDS",
    "OPERATORS",
    "Condition",
    "DetectionEngine",
    "DetectionRun",
    "Logic",
    "RuleDefinition",
    "RuleError",
    "RuleSet",
    "Threshold",
    "ThresholdHistory",
    "available_operators",
    "evaluate_condition",
    "evaluate_logic",
    "load_rule_document",
    "load_rule_file",
    "load_rules",
    "resolve_field",
    "rules_by_technique",
    "shannon_entropy",
]
