# Security Policy

SentinelFlow ingests and displays data that originates from untrusted sources —
security logs, command lines, URLs and file paths that an attacker may control.
Security is therefore a functional requirement of the project, not an add-on.

## Threat model

SentinelFlow is designed as a **local, single-analyst tool**. It ships with no
authentication and binds to `127.0.0.1` by default. It must not be exposed to a
network without placing authentication and TLS in front of it.

The adversary the design takes seriously is an attacker who **controls the
content of an ingested event**, and who wants to:

| Attacker goal | Control in SentinelFlow |
|---|---|
| Execute SQL through an event field | All database access goes through SQLAlchemy with bound parameters. No string-built SQL. |
| Inject script into the analyst's browser | Jinja2 autoescaping is asserted on, and no template or filter marks a value safe. Behind it, a Content-Security-Policy of `'self'` with no inline script or style means an injected script would have nowhere to run. Tests push `<script>` and attribute-breakout payloads through real ingestion into the rendered pages, and audit every template and rendered page for anything the policy would block. |
| Forge or flood log entries | Newlines are escaped and control characters stripped before logging; messages are truncated. See `app/core/logging.py`. |
| Leak credentials into logs | A redaction filter rewrites password/token/key-like values on every log record. |
| Override the AI's instructions (prompt injection) | Event data is passed to the model inside explicit untrusted-evidence delimiters, never concatenated into the system prompt, and the model's output is schema-validated before storage. The AI output can never change an alert's official severity. |
| Exhaust memory or disk | Upload size, event count and per-field length are capped by configuration. |
| Escape the data directory via a crafted path | No network-reachable endpoint takes a filesystem path: uploads arrive as *content*, and the filename is reduced to its final component and used only to choose a parser — never opened. For any caller whose path does cross a trust boundary, `resolve_within` resolves the path first, symlinks included, and only then checks it against an allow-list; checking before resolution is the classic mistake. |
| Double every event by replaying a request | Ingestion is idempotent by content: a byte-identical batch is recognised as a retry and stored once. A flaky network cannot manufacture a brute-force alert. |
| Reach an unauthenticated console over the network | `sentinelflow serve` refuses any non-loopback bind address unless `--expose` is passed, and warns loudly when it is. |
| Exhaust the stack with nested JSON | Nesting depth is capped and `RecursionError` is caught, so a bracket bomb becomes one rejected record rather than a crash. |
| Execute code through a rule file | Rules are parsed with `yaml.safe_load`, never `yaml.load`, whose default loader builds Python objects from `!!python/object/apply`. No rule content is ever evaluated: a rule names an operator and hands it data. |
| Hide an event by forward-dating it | Timestamps more than 24 hours in the future are rejected, so an event cannot be pushed off the bottom of a time-sorted queue. |
| Poison the verdict | The AI is advisory only. Severity, detections and MITRE mappings are produced by deterministic code and are always displayed separately from AI output. |

## What SentinelFlow deliberately does not do

* It does not execute, open or detonate any sample, file or URL found in an event.
* It does not call out to commercial threat-intelligence services.
* It does not make any network request at all when AI is disabled (the default).
* It does not auto-close, auto-escalate or auto-remediate. A human decides.
* It does not silently discard input. Every imported record becomes an event
  or a rejection with a stated reason, so a gap in the data is visible rather
  than invisible.
* It does not edit evidence. Defanged indicators (`hxxp://`, `evil[.]example`)
  are refanged on a copy used only for extraction; the stored event keeps
  exactly what arrived.
* It does not label extracted indicators as malicious. An indicator is a fact
  about a string that appeared in an event, and the model has no field in
  which to record a verdict.

## Handling credentials

* No credentials are required to run SentinelFlow.
* `.env` is gitignored; only `.env.example` is committed, and it contains
  placeholder values exclusively.
* Sample datasets contain synthetic usernames and hosts only. Never commit real
  logs, real hostnames or real credentials to this repository.

## Reporting a vulnerability

This is an educational portfolio project. If you find a security issue, please
open a GitHub issue describing the problem and how to reproduce it. Do not
include real credentials or real customer data in the report.
