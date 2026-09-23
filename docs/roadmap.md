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
| 4 | Event ingestion: JSON, CSV, adapters, generator | **Done** |
| 5 | IOC extraction engine | **Done** |
| 6 | Detection engine and YAML rule set (10+ rules) | **Done** |
| 7 | MITRE ATT&CK catalogue and evidence-backed mapping | **Done** |
| 8 | Deterministic severity engine | **Done** |
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

## Stage 4 - delivered

* `app/core/paths.py` - symlink-aware path confinement and a size check applied
  before a file is read
* Six adapters (Sysmon, Windows Security, firewall, DriftWatch,
  GhostCredential, canonical) with auto-detection; an explicit `--source`
  always wins over a guess
* `app/ingestion/parsers.py` - JSON arrays, single objects, NDJSON and wrapped
  arrays; CSV with delimiter detection and BOM handling; record count, field
  size and JSON nesting depth all bounded
* `app/ingestion/service.py` - the contract that an import never silently loses
  a record: every input becomes a stored event or a stored rejection with a
  reason. Idempotent by content hash; individual events deliberately not
  deduplicated
* `app/ingestion/generator.py` - a synthetic attack chain spanning four sources,
  plus reproducible benign background activity
* Schema version 2: `import_batches` and `rejected_events`, applied to an
  existing database by the migration runner
* CLI: `import`, `generate`, `demo`, `adapters`, `rejections`
* `docs/integrations.md` documenting every payload contract
* 156 new tests

## Stage 5 - delivered

* `app/enrichment/patterns.py` - every pattern paired with the rejection rule
  that makes it usable: version numbers are not addresses, filenames are not
  domains, hex blobs are not digests, arithmetic is not a path
* `app/enrichment/defang.py` - refangs `hxxp://` and `evil[.]example` on a copy
  only; the stored event keeps exactly what arrived
* `app/enrichment/extractor.py` - structured fields first (so the field name
  survives as context), free text second; bounded at 200 indicators per event
* `Indicator.is_internal` no longer relies on `ipaddress.is_private`, which is
  true for the RFC 5737 documentation ranges and would have labelled the demo
  scenario's external attacker as an internal host
* Schema version 3: `event_indicators`, so an indicator found inside a command
  line is reachable by the question correlation actually asks
* CLI: `indicators`, `extract`; `import` and `demo` now extract automatically
* `docs/ioc-extraction.md`
* 58 new tests, most of them about what must *not* be extracted

## Stage 6 - delivered

* `app/detection/operators.py` - the condition vocabulary. No rule content is
  ever executed: a rule names an operator and hands it data
* `app/detection/schema.py` - the rule language, with field names, operators,
  regexes, numeric arguments and technique IDs all validated at load time, so a
  typo cannot produce a rule that silently never fires
* `app/detection/loader.py` - `yaml.safe_load` only; a broken file is reported
  rather than taking the rest down; duplicate rule IDs are an error
* `app/detection/engine.py` - evaluation that shows its working, and threshold
  rules where a burst fires once, windows do not accumulate, and unattributable
  events are not counted
* 15 rules in `rules/`, including one that maps to no ATT&CK technique on
  purpose
* CLI: `rules`, `rules --validate`, `rules --by-technique`, `rules --sync`,
  `detect`
* `docs/detection-engine.md`
* 92 new tests, including 9 rules firing across the demo scenario and zero on
  120 events of benign background activity

## Stage 7 - delivered

* `data/mitre/techniques.json` - a curated offline subset: 30 techniques, all
  14 tactics, with its own provenance and attribution recorded. No network call
* `app/mitre/catalogue.py` - loads and validates it; a missing or broken file
  degrades rather than crashing, and `doctor` reports the gap
* `app/mitre/mapper.py` - builds every reason from the evidence that produced
  it, refuses techniques the catalogue cannot name, and says so when it falls
  back from a sub-technique to its parent
* Anti-fabrication enforced at three levels: rule validation, the mapper, and a
  database foreign key
* CLI: `mitre`, `mitre --coverage`, `mitre --technique`, `mitre --sync`;
  `rules --validate` now also checks every ATT&CK reference resolves
* `docs/mitre-attack.md`
* 37 new tests, most of them about what the mapper refuses to claim

## Stage 8 - delivered

* `app/services/context.py` - environment context: the critical hosts,
  privileged accounts and working hours this estate cares about, quoted by name
  in every factor that uses them
* `app/services/severity.py` - ten additive, explainable factors. The base is
  the worst rule rather than the sum, the same rule twice does not corroborate,
  and low confidence subtracts
* `app/services/alerting.py` - one alert per event carrying every rule that
  fired on it, with a title an analyst can triage from the queue
* `app/services/pipeline.py` - enrich, detect, map, score, alert; deterministic
  end to end, with the optional AI deliberately absent from the sequence
* Schema version 4: `events.triaged_at`, the first migration `create_all`
  cannot perform
* CLI: `triage`, `alerts`, `alert <id prefix>` with the full severity breakdown
* `docs/severity.md`
* 55 new tests, including three that assert the AI cannot influence a score
