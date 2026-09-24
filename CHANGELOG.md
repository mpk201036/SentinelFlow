# Changelog

All notable changes to SentinelFlow are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-09-24

### Added

- Six event adapters: canonical, Sysmon, Windows Security, firewall,
  DriftWatch and GhostCredential, with JSON, NDJSON and CSV ingestion.
- Bounded indicator extraction for addresses, domains, URLs, hashes, e-mail
  addresses, paths and processes, including defanged input.
- Fifteen validated YAML detection rules and an offline MITRE ATT&CK
  catalogue with evidence-backed mapping reasons.
- Deterministic, factor-by-factor severity scoring and transitive alert
  correlation into Potential Incidents.
- Analyst console, CLI and REST API over the same application services.
- Human workflow for status, classification, assignment and append-only notes
  and audit history, with stale-decision protection.
- Markdown, self-contained HTML and JSON reports with safe rendering and
  SHA-256 verification.
- Optional local Ollama analysis with prompt-injection warnings, grounding and
  a structural boundary that prevents model output changing the verdict.
- Reproducible demonstration scenario: 56 events, 9 alerts and one correlated
  investigation.
- Approximately 1,430 unit, integration, property, security, documentation and
  end-to-end tests, with line and branch coverage enforced above 90%.
- Release-ready wheel and source distribution containing all runtime rules,
  catalogue data, samples, console templates and static assets.

### Security

- Strict browser Content-Security-Policy, output escaping, request size and
  rate limits, path confinement, cross-site write protection, signed console
  form tokens, log redaction and append-only database triggers.

[Unreleased]: https://github.com/mpk201036/SentinelFlow/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mpk201036/SentinelFlow/releases/tag/v0.1.0
