# Build Roadmap

SentinelFlow is built in stages. A stage is complete only when its code, its
tests and its documentation are all done and the suite passes.

Legend: **Done** · *In progress* · Planned

## Milestone 1 — Foundation

| Stage | Scope | Status |
|---|---|---|
| 1 | Environment, repository, configuration, logging, CI | **Done** |
| 2 | Canonical event schema and domain models (Pydantic) | Planned |
| 3 | SQLite persistence, ORM models, schema init | Planned |

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
