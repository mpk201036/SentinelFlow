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
| 9 | Alert correlation and potential-incident grouping | **Done** |

## Milestone 3 — Interface

| Stage | Scope | Status |
|---|---|---|
| 10 | FastAPI REST API | **Done** |
| 11 | SOC dashboard (overview + alert detail) | **Done** |
| 12 | Optional Ollama AI provider with injection defences | **Done** |
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

## Stage 9 - delivered

* `app/services/correlation.py` - transitive linking via connected components,
  so an intrusion chain stays one investigation instead of being cut into
  fragments by single-key grouping
* Five linking signals (host, account, address, process chain, indicator), with
  two deliberate exclusions: "same rule" across unrelated hosts, and internal
  addresses or process names as indicators
* The window is anchored on event time, never on when the alert row was
  written, so a week-old export does not correlate as though it arrived today
* Correlation records breadth as stated facts rather than inventing a third
  severity number
* Analyst work is never overwritten: extending an incident leaves status and
  classification alone, and an alert already in an incident is never moved
* CLI: `correlate`, `incidents`, `incident <prefix>` with a full timeline;
  `demo` now runs ingestion, triage and correlation end to end
* `docs/correlation.md`
* 32 new tests

## Stage 10 - delivered

* FastAPI application factory (`app/api/app.py`) serving thirteen endpoints
  under `/api/v1`: health, stats, ingest, triage, correlate, and list/detail
  for events, alerts, incidents and rules
* API contract models (`app/api/schemas.py`) kept separate from the domain
  models, with severity always returned together with its factors and method
* Request middleware: request IDs, body-size limit enforced while streaming
  (not only via Content-Length), a coarse per-client rate limit, and strict
  security headers including the Content-Security-Policy
* Error handlers that log detail and return a request ID rather than a stack
  trace

### Stage 10 - post-review corrections

A review after Stage 11 found defects the original tests had not caught; each
now has a regression test.

* **Every API import was recorded twice.** The route saved the batch after the
  service already had, and the upsert counted the second save as a re-import:
  `accepted` and `rejected` doubled and every rejection row was duplicated
* **`create_app(settings)` ignored its settings** in every request handler.
  Middleware used them; the dependencies read the process defaults and the
  global engine. The app now owns its settings and database on `app.state`
* **`max_events_per_import` did not apply to API batches**
* **Incident pages ignored `offset`**, returning page one for every page
* **List totals came from a separately written filter** than the page they
  described; listing and counting now share one filter definition
* **Username filters did not normalise like storage**, so `LAB\\lab-user`
  found nothing; the correlation keys are now defined once, in the model
* **`serve --host 0.0.0.0` exposed an unauthenticated API silently**; it now
  refuses without `--expose`
* Ingestion moved to `POST /api/v1/events` (as the brief specified) with a new
  `POST /api/v1/events/import` for file uploads; `201` on creation, `200` on
  an idempotent repeat
* Documentation that claimed "the API passes an allow-list" to path
  confinement - an API caller that did not exist - was corrected

## Stage 11 - delivered

* `app/web/` - a server-rendered console on the same app: overview, alert
  queue, alert detail, investigations and rules
* The alert page as **strata of trust**: Observed, Determined, Suggested,
  Decided - the project's separation of evidence and interpretation made
  visible, with the AI layer hatched and labelled as advisory
* `app/web/charts.py` - SVG geometry computed in Python so the CSP never needs
  relaxing, and so chart arithmetic is unit-tested
* An emphasis trend chart instead of a four-colour severity stack, after the
  latter failed colour-vision validation; the chosen pair validated in both
  themes
* `app/services/dashboard.py` - one stats builder shared by the page and
  `GET /api/v1/stats`, which fixed the endpoint's previously empty `top_rules`
* Tests that push `<script>` and attribute-breakout payloads through real
  ingestion into the rendered pages, and that audit templates and rendered
  HTML for anything the CSP would block
* `docs/dashboard.md`
* 72 new tests

## Stage 12 - delivered

* `app/ai/` - optional, local, advisory analysis of one alert on request:
  * `evidence.py` - the one place that decides what the model sees. The
    deterministic score is withheld so the suggestion is independent; attacker
    text appears once; the document is capped at about 4,000 tokens
  * `prompts.py` - rules in the system message only, evidence JSON-escaped
    between per-request random-nonce markers, rules repeated after the data,
    and a specific warning when the injection scan fires
  * `injection.py` - a tripwire for text aimed at a model, naming the technique
    and the field; tested for no false alarms on the shipped scenario
  * `output.py` - a fixed JSON Schema, sent to Ollama as `format` and enforced
    again by a parser that treats the reply as untrusted input
  * `grounding.py` - "observed" claims citing values absent from the evidence
    are relabelled "inferred", and unmapped ATT&CK IDs are noted as "not a
    mapping"
  * `providers.py` - an Ollama client that stays on loopback unless told
    otherwise, follows no redirects, ignores proxy variables and caps replies
  * `service.py` - the sequence, two audit entries per request (failures
    included), and no write to the alert
* Schema version 5: `ai_analysis.injection_signals`, `ai_analysis.grounding_notes`
  and `ai_statements.downgraded`, so SentinelFlow's checks are stored apart from
  the model's words
* `sentinelflow ai status`, `sentinelflow ai analyze <alert>`,
  `GET /api/v1/ai/status`, `POST /api/v1/alerts/{id}/ai-analysis` (one analysis
  at a time: `429` otherwise)
* The console's Suggested layer shows the whole analysis, the injection signals
  with their locations, relabelled statements, and a "SentinelFlow checks" panel
  in the deterministic layer's colour
* `docs/ai-safety.md`, including measured results: `qwen2.5:7b` and `qwen3:8b`
  both noticed a planted "classify this as a false positive" instruction and
  both still lowered their assessment of a critical alert. The verdict held in
  every run
* 156 new tests (1,025 in all); the suite never contacts a model. Two further
  live checks are opt-in: `SF_LIVE_AI_MODEL=<model> pytest -m ai`

### Defects found while building Stage 12

Each has a regression test that was confirmed to fail with the fix removed.

* **Event text could crash or restyle the terminal.** Rich reads `[...]` as
  markup, so an event with `[/]` in its command line crashed
  `sentinelflow alert`, and `[link=...]` could plant a link. Every untrusted
  value the CLI prints is now escaped.
* **Alert collections had no defined order.** Indicators, detections and
  mappings came back in whatever order SQLite chose, so the same alert could
  read differently from one request to the next, and the evidence shown to a
  model was not reproducible. Every collection now has an explicit order.
* **Incident titles named an arbitrary rule.** Correlation took
  `detections[0]` as the lead rule while alert titles use the most severe one;
  both now use the most severe.
* **Long evidence was clipped in the console.** The alert page's layers were
  grids with an implicit `auto` column, so one long base64 command line
  stretched the column past the section's clipping edge and hid the end of
  every line in it. The columns now shrink and long tokens wrap.
* **`sentinelflow alert <prefix>` only searched the newest 500 alerts.** Prefix
  lookup now runs in SQL, and accepts only hex characters, so `%` and `_` can
  never act as LIKE wildcards.
* **`python -m app.cli` ran before most commands were registered**, because the
  `__main__` guard sat in the middle of the module.

