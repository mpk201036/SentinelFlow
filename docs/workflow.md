# Analyst workflow

The fourth layer of every alert — **Decided** — is the only one with authority.
Detection proposes, the optional model suggests, and an analyst decides. This
document covers what an analyst can decide, the rules that apply, how each
decision is recorded, and what stops anything else from making a decision in
the analyst's name.

All three interfaces use the same service, `AnalystWorkflow`
(`app/services/workflow.py`). A rule enforced in the console is enforced in the
API and the CLI too, because there is only one place it lives.

| | Console | API | CLI |
|---|---|---|---|
| Status, classification, assignee | Decision form, "Take it" | `PATCH /api/v1/alerts/{id}` | `sentinelflow decide <id> -s -c -a -r` |
| Investigation state, assignee | Decision form | `PATCH /api/v1/incidents/{id}` | `sentinelflow decide <id> --incident` |
| Notes | Note form | `POST /api/v1/{alerts,incidents}/{id}/notes` | `sentinelflow note <id> "..."` |
| History | History list | `GET /api/v1/{alerts,incidents}/{id}/audit`, `GET /api/v1/audit` | `sentinelflow history <id>` |

## 1. The rules, and why each exists

| Rule | Why |
|---|---|
| **Closing needs a classification.** `closed` and `benign` require one. | True- and false-positive rates are how rules get tuned. An alert closed without an answer teaches nobody anything. |
| **The answer must fit the outcome.** `benign` takes only *benign positive* or *false positive*; *needs more information* cannot be closed on. | A true positive filed as benign is a missed incident in every later report. |
| **Closing, reopening and escalating need a reason.** So do confirming, dismissing and reopening an investigation, and reclassifying a closed alert. | The reason travels with the change into the audit trail. It is the handoff note for whoever picks the alert up next, and the explanation a reviewer asks for later. |
| **Nothing goes back to *new* or *potential*.** | Once a human has looked, the record says so. Only the pipeline creates new alerts and only correlation creates potential incidents. |
| **No silent overwrites.** Every decision carries the version the analyst saw. | Two tabs, or the console and a script, cannot quietly undo each other. The second decision is refused with *"This alert changed after you opened it"*, and nothing is merged. |
| **A decision that changes nothing records nothing.** | The history stays a list of things that happened. |

Refusals are written for the analyst, say what to do next, and change nothing.
In the console the page comes back with the message beside the form and the
analyst's own input still in it, so a rejected closing note is not lost.

The version check is enforced in the database, not only in Python: the
`UPDATE` includes `WHERE updated_at = <the version read>`, so even a change
landing between the read and the write cannot be overwritten.

## 2. The record

Every change writes one audit entry: who (the configured analyst, or
SentinelFlow, or the AI assistant), what, the value before and after, the
reason, and the channel (`via console`, `via api`, `via cli`).

```text
SentinelFlow  Alert created           critical (90/100)
Miaad         AI analysis requested   provider=ollama model=qwen2.5:7b ... outcome=stored
AI assistant  AI analysis stored      suggested=medium deterministic=critical (unchanged)
Miaad         Alert status changed    New → Closed      Helpdesk created this account, ticket 4411 (via console)
Miaad         Alert classified        – → Benign positive
Miaad         Note added              Ticket 4411 attached.
```

Correlation now records what it did too: `incident_created` when it groups
alerts, `incident_extended` when a new alert joins an existing investigation.

**The history cannot be rewritten.** SQLite triggers refuse any `UPDATE` or
`DELETE` on `audit_log`, and any `UPDATE` on `analyst_notes`. Append-only is a
property of the database, not a convention the code has to remember. A note
that needs correcting gets a new note.

Schema version 6 brings existing databases forward. It rebuilds `audit_log` to
admit the new actions (SQLite cannot alter a CHECK constraint in place),
copies every row across unchanged, and installs the triggers.

## 3. Who "the analyst" is

SentinelFlow is a local, single-analyst tool with no login. The name recorded
on every decision comes from `SENTINELFLOW_ANALYST_NAME`, which defaults to the
operating-system account name. That is **attribution, not authentication**:
it records who was at the keyboard of this installation, and it proves nothing
to anyone who could edit the configuration. A multi-analyst deployment needs
real authentication in front of it, and would take the name from the
authenticated session instead.

## 4. Changes only from SentinelFlow itself

Once the console can close alerts, a page on another website must not be able
to do it through the analyst's browser. Two independent layers prevent that.

**Cross-site write guard** (`app/api/middleware.py`). Every `POST`, `PATCH`,
`PUT` and `DELETE` a browser marks as coming from elsewhere is refused with
`403`, across the whole application:

* `Sec-Fetch-Site` decides when present: only `same-origin` and `none`
  (typed into the address bar) are accepted. `same-site` is refused, because
  for a console on `localhost:8000`, a development server on `localhost:3000`
  is "the same site".
* Browsers without fetch metadata still send `Origin` on every POST; it must
  match the host.
* Clients that are not browsers (curl, scripts) send neither and are
  unaffected. The threat is a page acting through the browser, not a tool the
  analyst runs on purpose.

This covers endpoints no form token could protect, such as `POST
/api/v1/triage`, `/correlate` and `/ai-analysis`, which take no body at all.
A plain HTML form on any website could trigger them before this guard existed.

**CSRF tokens on every console form** (`app/web/csrf.py`), using the signed
double-submit pattern. A random value lives in an `HttpOnly`,
`SameSite=Strict` cookie; each form carries an HMAC of it under a secret that
exists only in the running process. A page elsewhere cannot read the cookie,
cannot compute the HMAC, and its cross-site request does not carry the cookie
at all. Restarting the server invalidates forms already on screen; the analyst
sees *"This form could not be verified"* and a link to reload. The cookie is
marked `Secure` whenever the console is exposed beyond loopback.

### A defect found in the browser, not in the tests

The first version of the guard refused the console's own forms. The test
client sends no browser headers, so every test passed. In a real browser the
decision form came back `403`, because the site's `Referrer-Policy:
no-referrer` makes browsers send `Origin: null` even on same-origin form
posts, which looks exactly like a sandboxed attacker page. Two changes fixed
it: `Sec-Fetch-Site`, which the page cannot set, now takes precedence over
`Origin`; and the policy became `same-origin`, which still sends nothing to
other sites, including the ATT&CK links, but keeps a real `Origin` on our own
posts for browsers without fetch metadata. The interface tests now send the
headers a browser sends, including the `Origin: null` case.

## 5. In the console

* **Take it** on a new alert: start investigating, assigned to you, in one
  click.
* **Record a decision**: status, classification, assignee and reason. Only the
  statuses you can actually move to are offered.
* **Notes**, which keep their line breaks and are shown as text, never markup.
* **History**, newest first, naming who acted. The marker shape repeats it at
  a glance: solid for an analyst, accent for SentinelFlow, dashed for the model.
* **Ask the local model**, when AI is enabled and usable. The button shows
  that the request is under way, because a local model can take a minute.

Every form posts, then redirects back with a fixed confirmation code
(Post/Redirect/Get), so reloading never submits twice. Confirmations appear in
the section the page returns to.
