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
| 13 | Analyst workflow: status, classification, notes, audit | **Done** |
| 14 | Investigation report generation (Markdown / HTML) | **Done** |

## Milestone 4 — Hardening and portfolio

| Stage | Scope | Status |
|---|---|---|
| 15 | Full test suite, integration tests, coverage | **Done** |
| 16 | Documentation set | **Done** |
| 17 | End-to-end demo scenario | **Done** |
| 18 | Repository polish, screenshots, release | **Done** |

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

## Stage 13 - delivered

* `app/services/workflow.py` - one `AnalystWorkflow` behind the console, the API
  and the CLI, so every rule lives in one place:
  * closing needs a classification that fits the outcome, and a reason
  * reopening, escalating, confirming and dismissing need a reason
  * nothing goes back to *new* or *potential*
  * a decision against an out-of-date view is refused (compare-and-swap on
    `updated_at` in the `UPDATE` itself), never merged
  * a decision that changes nothing records nothing
* An audit entry for every change: analyst, channel, before, after, reason.
  Correlation now audits `incident_created` and `incident_extended`
* Schema version 6: new audit actions (`alert_assigned`, `incident_assigned`,
  `incident_extended`) by rebuilding `audit_log` with every row kept, the first
  migration that needs a table rebuild; SQLite triggers make the audit log
  append-only and notes uneditable
* Console: "Take it", a decision form, notes and a history on every alert and
  investigation; "Ask the local model" from the alert page; an assignee column
  in the queue. Refusals come back beside the form with the analyst's input
  kept; successes use Post/Redirect/Get
* API: `PATCH /alerts/{id}`, `PATCH /incidents/{id}`, notes, per-record audit
  and `GET /api/v1/audit`
* CLI: `decide`, `note`, `history`, with `--incident` and `--assign me`
* `SENTINELFLOW_ANALYST_NAME`, recorded on every decision. It is attribution
  for a single local analyst, not authentication, and the docs say so
* Two layers against cross-site requests: a guard that refuses browser writes
  marked cross-site across the whole app (using `Sec-Fetch-Site`, then
  `Origin`), and signed double-submit CSRF tokens on every console form
* `docs/workflow.md`
* 89 new tests (1,114 in all). The interface tests send the headers a real
  browser sends

### Defects found while building Stage 13

Each has a regression test that was confirmed to fail with the fix removed.

* **The cross-site guard refused the console's own forms.** It passed every
  test, because the test client sends no browser headers, and failed on the
  first click in a real browser: `Referrer-Policy: no-referrer` makes browsers
  send `Origin: null` on same-origin form posts. `Sec-Fetch-Site` now decides
  when present, and the policy is `same-origin`, which still sends nothing to
  other sites.
* **Body-less API writes were open to cross-site requests.** `POST
  /api/v1/triage`, `/correlate` and `/ai-analysis` take no body, so a plain
  HTML form on any site could trigger them from the analyst's browser. The
  guard closes this for every write.
* **Reopening an alert kept its closing time.** `update_alert_status` stamped
  `closed_at` on close but never cleared it on reopen.
* **A quoted file path kept its closing quote.** `'C:\x\y.exe'` in a log message
  was extracted as `C:\x\y.exe'`, so it never matched the same path elsewhere:
  a wrong indicator in enrichment, and a false "not in the evidence" relabel in
  AI grounding, which is where a live `qwen2.5:7b` run exposed it.
* **Correlation left no trace in the audit trail** when it created or extended
  an investigation, although the action existed.
* **The audit log was append-only only by convention.** It is now enforced by
  the database.

## Stage 14 - delivered

* `app/reports/` - reports on one alert or a whole investigation, in
  Markdown, self-contained HTML and JSON, built once into a `Report` and laid
  out by each renderer, so the formats cannot disagree
* The order of trust carried into the report: summary and analyst conclusion,
  observed timeline, deterministic detections and evidence, ATT&CK mapped by
  rule, indicators, advisory AI (labelled, beside the unchanged verdict),
  decisions and notes, next steps, audit trail, scope and limitations. An
  unreviewed investigation says plainly that no compromise is asserted
* Safe to share: `md_text`, `md_code` and `md_block` keep event and model text
  from becoming links, images, raw HTML, headings or fence breaks; links,
  domains and e-mail addresses are defanged; the HTML file carries its own CSP
  with no script, no fetches and one stylesheet allowed by hash
* `defang_url`, `defang_email`, `defang_text` beside `refang`, in forms
  `refang` reverses
* Fingerprints: every export audited with the SHA-256 of its bytes;
  `sentinelflow verify-report` reports verified, modified or unknown
* CLI `report` and `verify-report`; API `GET /alerts/{id}/report` and
  `GET /incidents/{id}/report`; console Report and Markdown buttons.
  Cross-site exports are refused
* `app/core/display.py` - one description of an audit entry, shared by the
  console, the CLI and the reports, which had begun to disagree
* `docs/reports.md`
* 68 new tests (1,182 in all), including renderer-level tests that parse
  hostile reports with markdown-it and an HTML parser

### Defects found while building Stage 14

Each has a regression test that was confirmed to fail with the fix removed.

* **A refused CLI export was still audited.** The report was generated and
  recorded before the CLI checked whether it could write the file, so the
  trail showed an export that never happened. The check now comes first.
* **Identifiers in the HTML report were plain text**, not code as in the
  Markdown report, so a URL inside a hostile username would have been
  auto-linked by a mail client. Found by the test that parses hostile reports.
* **Three copies of "how an audit entry reads"** (console, CLI, report) had
  started to disagree; report exports showed no report ID. Now one module.

## Stage 15 - delivered

* Honest coverage: lines and branches, the CLI included (it had been excluded).
  87% with the CLI at 34% became 93% with the CLI at 76%; CI fails below 90%
* CI enforces types: the mypy step had `continue-on-error`, and the tests were
  never checked. `mypy app tests` now gates every build, with pydantic's mypy
  plugin
* Property-based fuzzing with Hypothesis at every untrusted-input boundary:
  sanitisers, defanging, Markdown escaping (checked by parsing), the model-reply
  parser, the injection scan, JSON and CSV ingestion, severity bounds, storage
  round trips, and the workflow under random decision sequences. A weekly CI
  job runs 2,000 examples per property
* `test_security_controls.py` - the rate limiter, streamed-body limits, the
  generic 500 and security headers on every kind of response, none of which a
  test had ever exercised
* `test_query_counts.py`, `test_reproducibility.py`, `test_end_to_end.py`,
  `test_cli_smoke.py` (every command against a demo database),
  `test_console_forms.py` (tampered, stale and dangling form submissions)
* Every test marked exactly one of unit, integration or ai, enforced at
  collection; `make test-fast` runs the unit tests in about five seconds
* `docs/testing.md`, mapping each claim in SECURITY.md to its tests
* 1,270 tests in all (86 new)

### Defects found by Stage 15's tests

Each code defect has a regression test confirmed to fail without its fix.

* **Truncation was not idempotent**: a stored, truncated field was truncated
  again on every load, with a wrong count
* **A chunked body over the limit got 400, not 413**: FastAPI's body parser
  caught the limit's exception
* **Unexpected 500s, and refusals from the outermost middleware, carried no
  request ID header or security headers**
* **N+1 queries** on the alert queue, the investigation page and the
  investigation report (85 queries for 25 alerts, now 13 at any size)
* **Tests marked as two kinds**: database-backed classes inside "unit" modules
  ran under `-m unit`
* **`assert` permitted in application code**, where `python -O` would strip it

## Stage 16 - delivered

* The documentation is tested: `tests/test_docs.py` checks every link and
  anchor, every CLI command and flag, every API path, every setting, every
  repository path, every rule and ATT&CK technique named, and every test cited
  in docs/testing.md against the code. It also checks the other direction:
  every command, route and page is documented somewhere
* `tests/test_migrations.py`: each migration brings a database at the version
  before it forward without losing data, and is safe to run twice. Versions 2
  to 4 had never run in a test
* README rewritten around a three-command quick start (`make setup`,
  `sentinelflow demo`, `sentinelflow serve`), a "what to look at" guide, an
  accurate pipeline diagram, and `generate` documented
* `docs/architecture.md` rewritten: the diagram, the responsibility table and
  the reasoning now match the code, including an honest account of what
  moving off SQLite would touch
* `docs/data-model.md` gained the tables, what may change in each, and the
  schema version history; SECURITY.md gained the rate limit, the generic
  error response and private vulnerability reporting
* About 1,380 tests in all (about 110 new)

### Defects found by Stage 16

* **The quick start crashed**: on a new machine, `sentinelflow demo` ended in
  a SQLAlchemy traceback because no command checked the schema first. Every
  command that reads stored data now checks it and says what to run; the demo
  creates a database when there is none; an out-of-date database is refused
  until `init-db` migrates it, and one from a newer release is left alone
* **`sentinelflow generate` rewrote the committed samples** by default, with
  today's timestamps. It now writes to `data/generated/`, which is ignored
* **Five false statements in the documentation**: a `--no-extract` flag that
  never existed, "extraction runs on import" (triage does it), a dangling
  link, a claim that migrations were tested, and four stale claims in the
  architecture page. `detect` also still said alerts would "arrive with the
  severity engine", eight stages after they did
* **"1 incidents created"**: counts and nouns now agree in every summary
* **The AI boundary test missed one import form**: it checked
  `from app.ai import ...` but not `import app.ai.service`
* **A regression in `serve`'s refusal would hang the suite** rather than fail
  it; the CLI tests now stub the server out

## Stage 17 - delivered

* `docs/demo-scenario.md`, a guided walkthrough of the demonstration: what the
  logs show, which rule fired, the ATT&CK mapping and the score for every
  alert, one score added up by hand, why the alerts became one investigation,
  the analyst's work in the console and on the command line, the report, and
  what SentinelFlow deliberately does not conclude
* `tests/test_demo_scenario.py` reads that page's tables and command block and
  checks them against a real `sentinelflow demo` run: every row, every number,
  the brief's five steps, the console, and the walkthrough's commands executed
  line by line, ending in a verified report
* The demo is anchored at 02:00 UTC on the most recent night wholly in the
  past, so its scores are the same whenever it is run and match the page;
  `sentinelflow demo` refuses to add a second copy without `--force`, and ends
  by naming the investigation it created and where to open it
* About 1,430 tests in all (about 45 new)

### Defects found by Stage 17

Running the demo as an analyst would, rather than as one import in a test,
found these. Each has a regression test confirmed to fail without its fix.

* **Verdicts depended on how events were batched.** Threshold rules counted
  within the current triage batch only, so eight failed logons triaged as
  they arrived never raised the brute-force alert. The repeat-activity factor
  counted only alerts from earlier runs, so the same events scored up to 20
  points apart. Both now read what earlier runs saw, and a feed triaged in
  batches of 1, 5 or 13 gives exactly the verdicts of one import. The repeat
  count is per event, strictly earlier, so a late import no longer borrows
  points from alerts that came after it
* **The demo's scores depended on the hour it was run**, through the
  out-of-hours factor
* **Running `demo` twice added a second copy of the attack** to the same
  investigation (21 alerts after three runs), because the data is dated from
  now and never looked like a duplicate
* **A confirmed investigation still said "awaiting analyst review"**: the
  status sentence was written into the summary at grouping time. The summary
  now states facts only, and says "and 3 more" rather than silently listing
  six of nine techniques
* **Reports called file hashes, paths and process names "external"**: nine
  indicators were "8 of them external" when two were. `Indicator.is_external`
  is now the one definition, and the three report formats share one scope
* **An author's YAML comment was printed as part of SF-0010's description**
  on every alert page and report: inside a folded block, `#` is text
* **On a short page at tablet width, the navigation bar grew to fill the
  spare height** (332 pixels), and a browser could keep serving the old
  stylesheet after an upgrade. The bar keeps its height, and asset URLs carry
  a content hash
* **The overview's headline was wrong twice over**: "1 potential
  investigations", counting confirmed investigations as potential
* **`make setup` required `python3.13`**, although 3.12 is supported and the
  README says so. It now uses the newest supported interpreter it finds, and
  says so plainly when there is none

## Stage 18 - delivered

* Three real console screenshots from a clean demonstration database: the
  overview, a critical alert and the correlated investigation. The README now
  shows the product before asking a visitor to install it
* `CHANGELOG.md`, `CONTRIBUTING.md`, `RELEASING.md`, structured issue forms and
  a pull-request template, so contribution and release expectations live in
  the repository rather than in one person's memory
* Release packaging now includes the 15 rules, ATT&CK catalogue, environment
  context, sample events, console templates and static assets. Runtime resource
  lookup supports both a source checkout and an installed wheel, while writable
  databases and logs remain outside the installation
* A package job in CI builds and checks the distributions, installs the wheel
  outside the checkout, then runs `doctor`, database setup and the full demo
* A tag workflow verifies that `vX.Y.Z` matches the package version, repeats
  the clean-wheel smoke test and publishes the wheel and source archive to a
  GitHub Release. Package-index publication remains deliberately manual
* `make build` and `make release-check` provide the same release gates locally

### Defects found by Stage 18

* **The wheel omitted almost every runtime resource.** Editable installs passed
  because the rules, catalogue and dashboard remained in the checkout, but a
  built wheel had only Python modules and report templates. A clean installed
  copy could not load rules, ATT&CK data, samples or the web console. Those
  resources now ship under `share/sentinelflow`, and CI runs the product away
  from the source tree
* **`sentinelflow doctor` failed before the first `init-db` in an installed
  copy.** The default `data/` directory did not exist yet, even though the
  database engine creates it safely. Doctor now checks the nearest existing
  writable parent and reports that the directory will be created
