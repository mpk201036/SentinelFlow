"""Optional, local, advisory AI analysis of alerts.

evidence    what the model is shown, decided in one place and size-bounded
injection   tripwire for text in the evidence that addresses a model
prompts     fixed rules, nonce-delimited evidence, a reminder after the data
output      the reply schema, and a parser that treats the reply as untrusted
grounding   downgrades "observed" claims the evidence does not support
providers   the Ollama client: loopback only, no redirects, bounded replies
service     the sequence, the audit entries, and nothing that touches an alert

Nothing in the deterministic pipeline imports this package.
"""

from app.ai.evidence import Evidence, build_evidence
from app.ai.grounding import GroundingResult, ground
from app.ai.injection import InjectionSignal, scan_evidence, scan_text
from app.ai.output import OUTPUT_SCHEMA, AIOutputError, ParsedReply, parse_reply
from app.ai.prompts import PROMPT_VERSION, Prompt, build_prompt
from app.ai.providers import (
    ModelProvider,
    OllamaProvider,
    ProviderConfigurationError,
    ProviderError,
    ProviderReply,
    ProviderStatus,
    ProviderUnavailableError,
    build_provider,
)
from app.ai.service import AIAnalysisService, AlertNotFoundError, AnalysisOutcome, OutcomeKind

__all__ = [
    "OUTPUT_SCHEMA",
    "PROMPT_VERSION",
    "AIAnalysisService",
    "AIOutputError",
    "AlertNotFoundError",
    "AnalysisOutcome",
    "Evidence",
    "GroundingResult",
    "InjectionSignal",
    "ModelProvider",
    "OllamaProvider",
    "OutcomeKind",
    "ParsedReply",
    "Prompt",
    "ProviderConfigurationError",
    "ProviderError",
    "ProviderReply",
    "ProviderStatus",
    "ProviderUnavailableError",
    "build_evidence",
    "build_prompt",
    "build_provider",
    "ground",
    "parse_reply",
    "scan_evidence",
    "scan_text",
]
