# Testing

SentinelFlow's claims are security claims: that hostile event text cannot
reach the analyst's browser or terminal, that a model cannot move a verdict,
that the record cannot be rewritten. A claim like that is only as good as the
test that would fail if it stopped being true. This document says how the
suite is organised, how it is run, and which tests stand behind each claim in
[SECURITY.md](../SECURITY.md).

## Running it

```bash
make test         # everything: about 1,270 tests, under a minute
make test-fast    # unit tests only: about 800, in about 5 seconds
make check        # what CI runs: lint, types (app and tests), tests with coverage
make fuzz         # the long property-based run: 2,000 examples per property
```

```bash
SF_LIVE_AI_MODEL=qwen2.5:7b pytest -m ai   # the two live checks against a local model
```

No test contacts a network or a model unless you ask for the `ai` tests.
Every test uses its own throwaway SQLite database and never reads your `.env`.

## What kinds of test there are

Every test is marked exactly one of three kinds. The collection hook in
`tests/conftest.py` refuses to run a test marked none or two, so `-m unit` is
always the fast subset. That rule fixed a real problem: a database-backed
class inside a module marked `unit` was both kinds, and ran under `-m unit`.

| Kind | What it covers | Count |
|---|---|---|
| `unit` | One component, no HTTP, no pipeline run | ~795 |
| `integration` | Several layers: API, console, CLI, pipeline, database | ~475 |
| `ai` | A real local model; skipped unless `SF_LIVE_AI_MODEL` is set | 2 |

Beyond ordinary example-based tests, five techniques each cover something the
others cannot:

| Technique | Where | What it catches |
|---|---|---|
| **Property-based fuzzing** (Hypothesis) | `test_properties.py` | Inputs nobody would write: control characters, backtick runs, deep JSON, random decision sequences |
| **Renderer-level parsing** | `test_reports.py`, `test_properties.py` | Reports parsed with markdown-it and an HTML parser, checking what *became* a link, image or heading |
| **Query counting** | `test_query_counts.py` | A page that starts issuing a query per row |
| **Reproducibility** | `test_reproducibility.py` | Any nondeterminism in scores, factors, mappings or grouping |
| **End to end over HTTP** | `test_end_to_end.py` | Pieces that pass alone but no longer fit together |

## Coverage

Coverage is measured on **lines and branches, with the CLI included**, and CI
fails below 90%. It was 93% when the floor was set.

Until this stage the CLI was excluded from measurement, which made the number
look better than it was: 94% without the CLI, 87% with it, and the CLI itself
at 34%. Smoke tests for every command (`test_cli_smoke.py`) brought it to 76%,
and the whole to 93%.

Coverage says which lines ran, not whether anything checked them, so the
important protections were also checked by **mutation**: remove the fix, and
confirm a test fails. That was done by hand for every defect fixed in Stages
12 to 15, and it found two weak tests. The first round-trip property passed
with the truncation bug in place, and a first reproducibility mutation was
cleaned away before the comparison ever saw it. Both were rewritten until they
failed for the right reason.

## Where each claim is tested

| Claim ([SECURITY.md](../SECURITY.md)) | Tests |
|---|---|
| SQL through an event field is inert | `test_database.py::…test_sql_metacharacters_are_stored_verbatim_and_harmlessly` |
| Script cannot reach the analyst's browser | `test_dashboard.py` (payloads through real ingestion into every page; template and rendered-HTML audits against the CSP) |
| Log lines cannot be forged; secrets are redacted | `test_logging.py::…newlines_cannot_forge…`, `…redaction_applies…` |
| Prompt injection is contained and flagged | `test_ai_analysis.py` (nonce markers, JSON escaping, scanner, no false alarms on the demo), `test_ai_service.py`, `test_ai_live.py` |
| Evidence stays on this machine | `test_ai_service.py::TestProviderConfiguration`, `::TestOllamaClient` (no redirects, no proxy environment, bounded replies) |
| The terminal cannot be restyled or crashed | `test_ai_interfaces.py::TestCli::test_event_text_cannot_restyle…`, `test_cli_smoke.py` |
| Memory and disk are bounded | `test_security_controls.py::TestBodySize` (including chunked bodies), `test_api.py` (413, event limits) |
| No path escapes the data directory | `test_paths.py` (traversal, absolute paths, symlinks), `test_api.py` (upload filename is a label only) |
| Replaying a request does not double events | `test_ingestion_service.py`, `test_api.py` (duplicate batch) |
| The console is not exposed by accident | `test_api.py::test_serve_refuses_a_non_loopback_address…`, `test_cli_smoke.py` |
| Nested JSON cannot exhaust the stack | `test_json_ingestion.py::…deeply_nested…`, `test_properties.py::TestIngestion` |
| A rule file cannot execute code | `test_rules.py::…yaml_python_object_tags_are_refused` |
| Events cannot be forward-dated | `test_event_schema.py::…far_future_timestamps_are_rejected` |
| Another site cannot act through the browser | `test_workflow_interfaces.py::TestCrossSiteGuard`, `::TestConsoleForms`, `test_console_forms.py` |
| History cannot be rewritten | `test_workflow.py::TestAuditTrail`, `::TestMigrationV6` |
| No decision silently overwrites another | `test_workflow.py::TestStaleDecisions`, `test_console_forms.py` |
| Reports cannot attack their reader | `test_reports.py::TestHostileReports`, `test_properties.py::TestReportEscaping` |
| An edited report is detected | `test_reports.py::TestFingerprints`, `test_end_to_end.py` |
| The verdict cannot be poisoned | `test_ai_boundary.py`, `test_ai_service.py::…verdict_does_not_move…`, `test_properties.py::TestWorkflowInvariants` |
| Rate limiting and generic errors behave | `test_security_controls.py::TestRateLimit`, `::TestErrors`, `::TestHeadersEverywhere` |
| The same events give the same verdict | `test_reproducibility.py` |

## What testing found in Stage 15

The code defects each have a regression test that was confirmed to fail without
its fix; the last two are enforced by the CI and lint configuration.

* **Truncation was not idempotent.** Models re-validate every value they load,
  so a field shortened at ingestion was shortened again on every read, and a
  command line stored as `[truncated 30 chars]` came back as `[truncated 23
  chars]`. Found while writing the sanitiser properties.
* **A chunked body over the size limit got `400`, not `413`.** FastAPI's body
  parser caught the limit's exception and reported malformed JSON. Memory was
  still bounded, but the documented response was false. The limit now answers
  itself once it is crossed.
* **An unexpected error's `500` carried no request ID header and no security
  headers.** It was produced outside the middleware that adds them.
* **Refusals from the outermost middleware had no security headers.**
* **Three pages issued a query per alert:** the alert queue, the investigation
  page, and the investigation report (three per alert: 85 queries for 25
  alerts, now 13 whatever the size).
* **CI never enforced types.** The mypy step ran with `continue-on-error`, and
  the tests were never type-checked. Both are enforced now, with pydantic's
  mypy plugin, which also made 22 old `type: ignore` comments unnecessary.
* **`assert` was allowed in application code.** Python's `-O` flag strips
  asserts, so a check written as one would vanish. The four that existed were
  invariants, not checks; they are explicit now, and ruff flags any new one.

## Known gaps

* **No browser automation in CI.** The console was checked in a real browser
  during development, and that is how a real defect was found: the
  cross-site guard refused the console's own forms under `Referrer-Policy:
  no-referrer`, which the test client could not show. The interface tests now
  send the headers a browser sends, but layout and JavaScript behaviour are
  verified by hand.
* **Model behaviour is observed, not tested.** Whether a model is steered by an
  injection varies by model and run; `docs/ai-safety.md` records what was
  measured. The tests check only what must hold for any model.
* **Concurrency is tested at the SQL level, not under load.** The
  compare-and-swap is tested directly; many simultaneous analysts are not.
