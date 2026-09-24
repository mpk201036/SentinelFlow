# Releasing SentinelFlow

Releases are built from signed-off source on `main`. A version tag triggers
`.github/workflows/release.yml`, which builds the wheel and source archive,
checks their metadata, installs the wheel outside the checkout, runs the demo,
and creates a GitHub Release containing both artifacts.

## Prepare

1. Choose a semantic version such as `0.1.1`.
2. Update `version` in `pyproject.toml` and `__version__` in `app/__init__.py`.
3. Move the relevant entries in `CHANGELOG.md` from Unreleased into a dated
   version section and update its comparison links.
4. Run the complete release gate:

```bash
make release-check
```

5. Install the built wheel in a clean environment and run `sentinelflow demo`
   if the release changes packaging, resources or startup behavior.

## Tag and publish

```bash
git tag -a v0.1.0 -m "SentinelFlow 0.1.0"
git push origin v0.1.0
```

The tag must exactly match the package version with a leading `v`; the release
workflow refuses a mismatch. Publishing to a package index is deliberately not
automated. GitHub Release artifacts are the supported distribution for this
portfolio project.

## Verify

- Download the wheel from the GitHub Release into a clean Python 3.12 or 3.13
  environment.
- Run `sentinelflow doctor`, `sentinelflow init-db`, `sentinelflow demo`, and
  `sentinelflow serve`.
- Confirm that the overview, alert detail, investigation and Rules pages load
  without using a source checkout.
