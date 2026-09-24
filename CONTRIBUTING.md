# Contributing to SentinelFlow

Thank you for improving SentinelFlow. This project values changes that are
small, explainable and backed by a test that would fail if the behavior broke.

## Before starting

- For a security vulnerability, use the private process in
  [SECURITY.md](SECURITY.md), not a public issue.
- For a bug or feature, open an issue first when the change affects the data
  model, rule language, public API or trust boundary.
- Never include real logs, credentials, hostnames or customer data. Use the
  synthetic generator and documentation address ranges.

## Set up a development environment

```bash
git clone https://github.com/mpk201036/SentinelFlow.git
cd SentinelFlow
make setup
source .venv/bin/activate
sentinelflow doctor
```

## Make a change

1. Keep observations, deterministic conclusions, AI suggestions and analyst
   decisions separate.
2. Add or update tests with the code.
3. Update documentation when a command, flag, route, setting, rule or behavior
   changes. Documentation is checked against the application in CI.
4. Run `make check` before opening a pull request.

For a new detection, edit YAML under `rules/`, run
`sentinelflow rules --validate`, then use `sentinelflow detect` for a no-write
trial. Include both a positive example and benign activity that must not fire.

For a new source, add one adapter under `app/ingestion/adapters/`, register it,
preserve unknown fields in `raw_event`, and test both accepted and rejected
records.

## Quality checks

```bash
make test-fast       # fast unit subset
make lint            # ruff and formatting
make typecheck       # mypy on app and tests
make check           # the same quality gates as CI
make release-check   # quality gates plus package build and metadata checks
```

The full suite should make no network request and should not contact a model.
Live AI tests are opt-in and require `SF_LIVE_AI_MODEL`.

## Pull requests

Explain the problem, the design choice, the tests, and any security or data
migration effect. Keep generated databases, reports, logs, coverage files and
real event data out of commits. By contributing, you agree that your work is
licensed under the repository's MIT License.
