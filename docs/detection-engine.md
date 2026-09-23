# Detection Engine

## Rules are data

A detection lives in `rules/*.yaml`. Adding one requires no Python change and
no redeploy — which is how detection engineering actually works. Content and
code have different authors, different review cycles, and different people who
need to read them.

```yaml
id: SF-0003
name: Encoded PowerShell command
description: >
  PowerShell was invoked with an encoded command block. Encoding is a
  legitimate feature, but it also hides the command from anyone reading the
  logs, which is why it appears in so much tooling.
severity: high
confidence: high
mitre: [T1059.001, T1027]
false_positives:
  - Configuration management tools frequently use -EncodedCommand.
recommendation: >
  Decode the base64 block and read the command before deciding anything.
detection:
  event_types: [process_creation]
  all:
    - field: process_name
      operator: contains
      value: [powershell, pwsh]
    - field: command_line
      operator: regex
      value: '(?:^|\s)-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}'
      label: carries an encoded command block
```

## Relationship to Sigma

The language borrows Sigma's vocabulary — `contains`, `startswith`, `endswith`,
`re`, `cidr` — so the idiom is familiar to anyone who has written detections.
It differs in one place: the operator is written as a field rather than encoded
in the key (`field|contains:`).

Sigma's modifier syntax is more compact. An explicit operator is easier to
validate, produces a better error message when it fails, and can be read by
someone who has never seen Sigma. A Sigma importer that emits this format is a
natural extension rather than a rewrite.

## Failing loudly is the point

A detection stack where a typo produces a rule that silently never fires is
worse than one that refuses to start. It *looks* like coverage. So everything
that can be checked is checked when the file loads, not when an alert is being
triaged:

| Checked at load | Why |
|---|---|
| **Field names** against the event schema | `proces_name` would never match anything, and nobody would notice |
| **Operator names** against the registry | Same failure mode, with a list of alternatives in the error |
| **Regular expressions** compile | A broken pattern fails at startup with the file name attached |
| **Numeric arguments** parse | `length_gt: "lots"` is caught before it matters |
| **ATT&CK technique IDs** match the format | Stops a typo becoming a fabricated mapping |
| **Duplicate rule IDs** across all files | Otherwise one silently wins and nobody can tell which fired |
| **Rules that only exclude** | A rule with only a `none` block matches every event |

A broken file does not stop the others loading. It is collected and reported:

```bash
sentinelflow rules --validate
```

## Two safety properties

**No rule content is ever executed.** There is no `eval`, no lambda, no import
hook. A rule names an operator from `app/detection/operators.py` and hands it
data. Rule files are trusted content — like code — but a malicious one cannot
become arbitrary execution by accident, which is exactly what a "it's only
config, just use eval" design allows.

**`yaml.safe_load`, never `yaml.load`.** PyYAML's default loader constructs
arbitrary Python objects from tags like `!!python/object/apply`. That turns a
rule file into a deserialisation sink. There is a test that feeds the loader
exactly that payload and asserts it is refused.

## Conditions

```yaml
detection:
  event_types: [process_creation]   # cheap pre-filter
  all:  [...]                       # every condition must match
  any:  [...]                       # at least one must match
  none: [...]                       # none may match
```

`none` exists because most real rules are *"this pattern, except when it is our
own tooling"*, and an exclusion list reads far better than a negated operator
buried among the positives.

### Operators

| Group | Operators |
|---|---|
| String | `equals`, `not_equals`, `contains`, `not_contains`, `contains_all`, `startswith`, `endswith`, `regex`, `not_regex` |
| Presence | `exists` |
| Size | `length_gt`, `entropy_gt` |
| Numeric | `gt`, `gte`, `lt`, `lte` |
| Network | `cidr`, `not_cidr`, `is_private` |

List fields are tested element by element, so `tags contains deception` means
"one of the tags contains it" — what a rule author expects.

`entropy_gt` uses Shannon entropy in bits per character. Encoded or packed
content sits around 4.5–6; ordinary commands and paths sit nearer 3.5, because
they are made of words. It is a heuristic, which is why the rule that uses it
is rated low and pairs it with a length check and an exclusion list.

### Fields

Every field on the canonical event, plus the derived correlation keys
(`hostname_key`, `username_key`, `process_name_key`), plus `raw_event.<key>`
for reaching into the untouched original record. Raw lookups are
case-insensitive: the same Windows export writes `EventID`, `eventid` or
`event_id` depending on what produced it, and a rule should not have to know
which.

## Threshold rules

Some detections are not a property of any single event. "Five failed logons for
one account within ten minutes" needs counting.

```yaml
detection:
  event_types: [authentication_failure]
threshold:
  count: 5
  within_minutes: 10
  group_by: [hostname_key, username_key]
```

Three behaviours worth knowing:

* **A burst fires once.** After the threshold is reached the window resets, so
  nine failures produce one detection, not five. An analyst wants to know a
  burst happened, not receive one alert per event in it.
* **Events outside the window do not accumulate.** Five failures over five
  hours is not a brute-force attempt.
* **Events missing a group key are not counted.** Activity that cannot be
  attributed to a host and account must not be counted as if it could — that
  would be a guess wearing a number.

## Every detection shows its working

```
Encoded PowerShell command (SF-0003) matched because
  process_name contains powershell, pwsh -> powershell.exe;
  command_line carries an encoded command block -> powershell.exe -nop -w hidden -enc JAB...
```

A `DetectionResult` carries the field, the test and the observed value for
every condition that contributed. It also **snapshots the rule** as it was when
it matched, so editing a rule next month does not rewrite the history of alerts
it produced last month.

This is the difference the whole project turns on. A language model can produce
a more fluent explanation. It cannot produce a reproducible one.

## Restraint about ATT&CK

`SF-0010` (newly exposed network service) maps to **no** technique, and that is
deliberate. ATT&CK describes adversary behaviour; exposing a service is a
configuration change. `T1133 External Remote Services` covers an adversary
*using* such a service to get in, which the evidence does not show.

Attaching it anyway would make the rule look more thorough and be wrong. A
mapping an analyst cannot justify is worse than no mapping, because the first
time someone checks one and finds it hollow, they stop checking the rest.

## What ships

15 rules covering repeated authentication failures, external logons, encoded
PowerShell, download primitives, Office spawning script hosts, execution from
temporary directories, account creation, privileged group changes, service
installation, scheduled tasks, log clearing, decoy credential access, newly
exposed services, external connections from script hosts, and high-entropy
command lines.

Against the demonstration scenario, nine rules fire across the attack chain.
Against 120 events of benign background activity, **zero** fire — which is the
number that decides whether anyone will actually use the tool, and there is a
test asserting it stays zero.

## Using it

```bash
sentinelflow rules                  # list them
sentinelflow rules --validate       # exits non-zero if any file is broken
sentinelflow rules --by-technique   # ATT&CK coverage
sentinelflow rules --sync           # mirror into the database
sentinelflow detect                 # evaluate stored events and show what fires
```

`detect` stores nothing. Alerts are created once the severity engine exists,
because an alert without a severity is not something an analyst can queue.
