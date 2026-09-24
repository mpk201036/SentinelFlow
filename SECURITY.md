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
| Override the AI's instructions (prompt injection) | Event data is JSON-escaped and placed between markers carrying a per-request random nonce, never in the system prompt; the rules are repeated after the data. A heuristic scan flags text aimed at a model and names the field. The reply must match a fixed schema, keys claiming authority (`severity`, `status` ...) are discarded, and "observed" claims the evidence does not support are relabelled. Nothing the model says can change an alert. See [docs/ai-safety.md](docs/ai-safety.md), including a measured case where a model was steered and the verdict held. |
| Exfiltrate evidence through the AI provider | The provider must be on loopback unless `SENTINELFLOW_AI_ALLOW_REMOTE_PROVIDER` is set. The client follows no redirects, ignores proxy environment variables and caps the response size. The provider URL may not carry credentials. |
| Restyle or crash the analyst's terminal | Rich reads `[...]` as markup: an event with `[/]` in its command line used to crash `sentinelflow alert`, and `[link=...]` could plant a link. Every value that came from an event, a file or a model is escaped before the CLI prints it. |
| Exhaust memory or disk | Request bodies, uploads, events per import and field lengths are capped by configuration. The body limit is enforced as bytes arrive, so a chunked request with no declared length is cut off at the limit rather than read in full. |
| Fill the database in a loop | A per-client limit on requests per minute (`SENTINELFLOW_API_RATE_LIMIT_PER_MINUTE`, 600 by default) answers `429`. It is coarse on purpose: it stops a misconfigured importer, and a per-process counter would not stop a determined attacker. |
| Learn the internals from an error | An unexpected failure returns a generic `500` with a request ID and nothing else; the detail goes to the log under that ID. Every response, refusals and errors included, carries the security headers. |
| Escape the data directory via a crafted path | No network-reachable endpoint takes a filesystem path: uploads arrive as *content*, and the filename is reduced to its final component and used only to choose a parser — never opened. For any caller whose path does cross a trust boundary, `resolve_within` resolves the path first, symlinks included, and only then checks it against an allow-list; checking before resolution is the classic mistake. |
| Double every event by replaying a request | Ingestion is idempotent by content: a byte-identical batch is recognised as a retry and stored once. A flaky network cannot manufacture a brute-force alert. |
| Reach an unauthenticated console over the network | `sentinelflow serve` refuses any non-loopback bind address unless `--expose` is passed, and warns loudly when it is. |
| Exhaust the stack with nested JSON | Nesting depth is capped and `RecursionError` is caught, so a bracket bomb becomes one rejected record rather than a crash. |
| Execute code through a rule file | Rules are parsed with `yaml.safe_load`, never `yaml.load`, whose default loader builds Python objects from `!!python/object/apply`. No rule content is ever evaluated: a rule names an operator and hands it data. |
| Hide an event by forward-dating it | Timestamps more than 24 hours in the future are rejected, so an event cannot be pushed off the bottom of a time-sorted queue. |
| Make the analyst's browser change something (CSRF) | Every state-changing request a browser marks as cross-site is refused, using `Sec-Fetch-Site` and falling back to `Origin`; this covers body-less endpoints such as triage and correlation, which a plain form on any site could otherwise trigger. Console forms also carry a signed double-submit token (`HttpOnly`, `SameSite=Strict` cookie; HMAC under a per-process secret). See [docs/workflow.md](docs/workflow.md). |
| Rewrite history | SQLite triggers refuse `UPDATE` and `DELETE` on the audit log and `UPDATE` on analyst notes. Every analyst change is audited with the analyst, the channel, before and after, and the reason. |
| Overwrite another decision unseen | Decisions carry the version the analyst saw and are applied with a compare-and-swap `UPDATE`; a stale decision is refused, never merged. |
| Attack the reader of a report | Report prose is escaped so event text cannot become a link, an image (a tracking pixel), raw HTML or a forged heading; verbatim evidence sits in code blocks it cannot close; URLs, domains and e-mail addresses are defanged. The HTML report is one file with its own CSP: nothing fetched, no script, one stylesheet allowed by hash. Tests parse reports with a Markdown parser and an HTML parser, as a renderer would. See [docs/reports.md](docs/reports.md). |
| Pass off an edited report as genuine | Every export records the SHA-256 of the exact bytes in the audit trail; `sentinelflow verify-report` says whether a copy is verified, modified or unknown. Tamper evidence for readers who do not control the database, not tamper prevention. |
| Poison the verdict | The AI is advisory only. Severity, detections and MITRE mappings are produced by deterministic code and are always displayed separately from AI output. |

## What SentinelFlow deliberately does not do

* It does not execute, open or detonate any sample, file or URL found in an event.
* It does not call out to commercial threat-intelligence services.
* It does not make any network request at all when AI is disabled (the default),
  and when AI is enabled it sends evidence only to a model on this machine unless
  told otherwise.
* It does not let a model decide. The model is not shown the deterministic
  score, and its suggestion is stored and displayed beside the verdict, never in
  place of it.
* It does not auto-close, auto-escalate or auto-remediate. A human decides,
  and the record says which human, when and why. That identity is the
  configured analyst name: attribution for a single local analyst, not
  authentication.
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

This is an educational portfolio project, but a report is still welcome.
Please report privately, through GitHub's **Report a vulnerability** button on
the repository's Security tab, rather than in a public issue, so the problem
is not published before it is fixed. Include what you did and what happened.
Do not include real credentials or real customer data.
