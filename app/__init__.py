"""SentinelFlow — AI-Assisted Security Alert Triage System.

A local-first security alert triage platform built around a strict separation
between deterministic detection logic and optional, advisory AI analysis.

The deterministic pipeline (normalisation, IOC extraction, detection, MITRE
mapping, severity scoring, correlation) is the authoritative source of truth.
Any AI output is advisory, clearly labelled, and never authoritative.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
