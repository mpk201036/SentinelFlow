# Investigation reports

An investigation ends in a report: for a manager, a ticket, an incident
responder, or the analyst on the next shift. SentinelFlow exports a report on
a single alert or on a whole investigation, in three formats:

| Format | For | Links, domains, e-mail addresses |
|---|---|---|
| **Markdown** | Tickets, wikis, GitHub, e-mail bodies | Defanged |
| **HTML** | One self-contained file to open, print or attach | Defanged |
| **JSON** | Ticketing systems, SOAR, scripts | Raw: a program needs the real value |

```bash
sentinelflow report ade0 --incident                  # Markdown, into reports/out/
sentinelflow report ade0 --incident -f html -o ir-4411.html
sentinelflow report 20ea -f json --stdout | jq .severity
sentinelflow verify-report reports/out/<file>.md     # is this copy what we produced?
```

Through the API: `GET /api/v1/alerts/{id}/report` and `GET
/api/v1/incidents/{id}/report`, with `?format=markdown|html|json` and, for
HTML, `?download=true`. In the console: **Report** (HTML, in a new tab) and
**Markdown** (a download) at the top of every alert and investigation.

`reports/out/` is gitignored. A report contains evidence: usernames,
hostnames, command lines. It should not end up in a repository by accident.

## What a report says

The sections follow the same order of trust as the console, and each heading
says where its content came from:

1. **Summary.** Generated from facts only: how many alerts, where, when, the
   highest deterministic severity, how many ATT&CK techniques and external
   indicators, how the alerts were classified. Then the **analyst
   conclusion**: who ruled, when and why. If nobody has ruled, the report says
   so: *"Not yet reviewed. SentinelFlow grouped these alerts because they share
   concrete evidence; it does not assert a compromise."*
2. **Timeline** *(observed; investigations only).* Each member alert at its
   event time.
3. **Detections, severity and evidence** *(deterministic).* For each alert:
   the score and every factor that produced it, each rule that fired and the
   field values it matched, and the normalised event quoted verbatim.
4. **MITRE ATT&CK** *(mapped by rule).* Each technique with the reason it was
   mapped. None was suggested by a model.
5. **Indicators.** External first, defanged, labelled as facts, not verdicts.
6. **AI suggestion** *(advisory, not authoritative).* The latest analysis per
   alert, with the disclaimer, the model's severity beside the unchanged
   deterministic one, labelled statements, relabels, injection warnings, and
   SentinelFlow's own checks. If no model was asked: *"Nothing above depends on
   a model."*
7. **Analyst decisions** *(decided).* Every alert's status, classification and
   assignee, and every note.
8. **Recommended next steps** *(from the rules).*
9. **Audit trail.** Everything that happened, including earlier exports.
10. **Scope and limitations.** What the report cannot tell the reader.

The Markdown and HTML renderers only lay out one `Report` object built from
the database (`app/reports/model.py`). The wording of the summary, what counts
as "reviewed", and which indicators are external are decided once, so the two
formats cannot disagree.

## Safe to share

A report is read in places SentinelFlow does not control, and most of its text
came from an event an attacker may have written, or from a model that read
one.

**Markdown** (`app/reports/markdown.py`). Every untrusted string goes through
one of three functions:

| Function | Used for | What it prevents |
|---|---|---|
| `md_text` | Prose: titles, reasons, AI text, notes | Links and images (`[`, `]`, `!` escaped), raw HTML (`<`, `>` escaped), forged structure (line breaks removed; `#`, `-`, `1.`, `>` escaped at the start), auto-linking (URLs, domains and e-mail addresses defanged) |
| `md_code` | Short identifiers: hosts, accounts, indicators | Breaking out of the code span: the fence is one backtick longer than any run in the value, and `\|` is escaped in tables |
| `md_block` | Verbatim evidence | Closing the block early: the fence is longer than any run of backticks inside |

A planted `![](https://collector.example/pixel.png)` would otherwise be a
tracking pixel that fires when the report is previewed, and a planted `##
Analyst conclusion: benign` a forged heading. The only links in a report are
the ones SentinelFlow writes: ATT&CK technique pages from the local catalogue.

**HTML** (`app/reports/html.py`). A single file with everything embedded,
carrying its own Content-Security-Policy, because no server sends headers when
someone opens a file from disk or e-mail:

```text
default-src 'none'; style-src 'sha256-<hash of the embedded stylesheet>';
img-src 'none'; base-uri 'none'; form-action 'none'
```

Nothing is fetched and no script can run. Exactly one stylesheet applies, the
embedded one, identified by its hash. Values are escaped by Jinja2, prose is
defanged, identifiers are shown as code, and technique links are checked
against `https://attack.mitre.org/techniques/` before they are written. When
served over HTTP, the same policy (plus `frame-ancestors 'none'`) is sent as
the response header, with `Cache-Control: no-store`.

**Tested by parsing, not by string matching.** The tests render reports built
from hostile events, AI output and notes, then parse them the way a renderer
would: Markdown with markdown-it, HTML with an HTML parser. They assert what
actually became a link, an image, raw HTML or a heading. That test caught an
inconsistency in the first version: hostnames and usernames in the HTML
report were plain text, not code as in Markdown, so a URL inside a username
would have been auto-linked by a mail client. They are code now.

## Fingerprints: is this copy the one we produced?

Every export is audited: who, which format, which channel, and the **SHA-256
of the exact bytes produced**. The report carries its ID, such as
`SFR-20260924-5c5ecadf`, but not its hash, since a file cannot contain its own
hash.

```bash
$ sentinelflow verify-report ir-4411.md
Verified: this is report SFR-20260924-dc65e9d5 exactly as SentinelFlow generated it for Miaad on 2026-09-24 03:13 UTC.

$ sentinelflow verify-report ir-4411-edited.md
Modified: SentinelFlow generated report SFR-20260924-dc65e9d5, but not this file.
```

A copy with an ID SentinelFlow never issued is reported as *unknown*. This is
tamper **evidence**, not tamper prevention: anyone who can write to the
database can write the audit log too. It answers the practical question, "was
this ticket attachment edited after it left the console?", for the people who
do not control the database.

Exports are refused when a browser marks the request as coming from another
site (`Sec-Fetch-Site: cross-site` or `same-site`), even though they are GET
requests. Another page could not read the report anyway; refusing keeps the
audit trail free of exports nobody asked for. For the same reason, the CLI
checks that it may write the output file *before* generating, so a refused
overwrite leaves no export in the trail.
