# Build Roadmap

SentinelFlow is built in stages. A stage is complete only when its code, its
tests and its documentation are all done and the suite passes.

Legend: **Done** · *In progress* · Planned

## Milestone 1 — Foundation

| Stage | Scope | Status |
|---|---|---|
| 1 | Environment, repository, configuration, logging, CI | **Done** |
| 2 | Canonical event schema and domain models (Pydantic) | **Done** |
| 3 | SQLite persistence, ORM models, schema init | **Done** |

## Milestone 2 — Pipeline

| Stage | Scope | Status |
|---|---|---|
| 4 | Event ingestion: JSON, CSV, adapters, generator | Planned |
| 5 | IOC extraction engine | Planned |
| 6 | Detection engine and YAML rule set (10+ rules) | Planned |
| 7 | MITRE ATT&CK catalogue and evidence-backed mapping | Planned |
| 8 | Deterministic severity engine | Planned |
| 9 | Alert correlation and potential-incident grouping | Planned |

## Milestone 3 — Interface

| Stage | Scope | Status |
|---|---|---|
| 10 | FastAPI REST API | Planned |
| 11 | SOC dashboard (overview + alert detail) | Planned |
| 12 | Optional Ollama AI provider with injection defences | Planned |
| 13 | Analyst workflow: status, classification, notes, audit | Planned |
| 14 | Investigation report generation (Markdown / HTML) | Planned |

## Milestone 4 — Hardening and portfolio

| Stage | Scope | Status |
|---|---|---|
| 15 | Full test suite, integration tests, coverage | Planned |
| 16 | Documentation set | Planned |
| 17 | End-to-end demo scenario | Planned |
| 18 | Repository polish, screenshots, release | Planned |

## Stage 1 — delivered

* Repository skeleton, MIT licence, `.gitignore` with secret/database exclusions
* `pyproject.toml` with pinned lower bounds, ruff, mypy, pytest and coverage config
* `app/core/config.py` — environment-driven settings, validated, with safe
  defaults (loopback binding, AI disabled, bounded ingestion limits)
* `app/core/logging.py` — credential redaction and log-injection defence
* `app/cli.py` — `version`, `config`, `doctor`
* `Makefile`, GitHub Actions CI across Python 3.12 and 3.13
* 60+ tests covering configuration, logging safety and repository hygiene

## Stage 2 - delivered

* `app/core/sanitize.py` - normalisation for untrusted values: Unicode NFC,
  removal of zero-width and bidi-override characters, marked truncation,
  canonical IP/domain/hash/email forms
* `app/models/enums.py` - controlled vocabularies, including a `Severity` that
  is ordered by rank rather than alphabetically
* `app/models/base.py` - frozen `EvidenceModel` vs mutable `WorkflowModel`,
  UTC coercion, implausible-timestamp rejection, bounded raw payloads
* `SecurityEvent` - the canonical schema; observation only, no verdict fields
* `Indicator`, `DetectionResult`, `MitreTechnique`/`MitreMapping` (reason
  mandatory), `AlertSeverity`/`Alert`, `Incident`, `AIAnalysis`, `AnalystNote`,
  `AuditEntry`
* `docs/data-model.md` with a class diagram and the rationale for the three
  deviations from the original flat schema
* 188 new tests, including `tests/test_ai_boundary.py`, which asserts the
  deterministic/AI separation structurally

## Stage 3 - delivered

* `app/database/base.py` - `UtcDateTime` (SQLite returns naive datetimes from a
  plain timezone-aware column, which would shift every correlation window) and
  enum columns stored as API values with a real CHECK constraint
* `app/database/session.py` - engine factory with the SQLite pragmas that
  matter: `foreign_keys=ON` (off by default), WAL, busy timeout
* `app/database/tables.py` - 16 tables; `ai_analysis.is_advisory` carries a
  CHECK constraint and `mitre_mappings.technique_id` is a foreign key into the
  ATT&CK catalogue, so fabricated techniques are refused by the schema
* `app/database/init_db.py` - idempotent creation, `schema_version` stamping
  and an ordered migration runner
* `app/database/mappers.py` and `repository.py` - the rest of the application
  asks for domain objects and never sees a row or writes a query
* CLI: `sentinelflow init-db`, `sentinelflow db-info`; `doctor` now checks the
  schema version
* 44 new tests, mostly integration against a real SQLite file
