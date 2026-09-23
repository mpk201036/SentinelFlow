# Severity Engine

## What severity is for

Severity is the number an analyst uses to decide what to look at first. Two
properties matter more than sophistication:

* **It is reproducible.** The same inputs always produce the same score. No
  randomness, no clock, no model.
* **It shows its working.** Every point is attached to a named factor with a
  sentence explaining why it applied.

An analyst who disagrees with a score can see exactly which factor to argue
with. A detection engineer can see exactly which weight to change. Neither is
possible with a score that arrives as a bare number.

```
How the severity was calculated (deterministic)
   +65  rule_severity         Rule SF-0006 (Account added to a privileged group) is HIGH severity
    +5  detection_confidence  Rule SF-0006 is high confidence
   +15  privileged_account    svc-helper matches the privileged account pattern 'svc-*'
    85  total -> critical
```

## Why scoring is additive

Multiplicative scoring produces numbers nobody can reason about backwards. A 72
that came from `0.8 × 0.9 × 100` cannot be explained in a sentence.
*"65 because the rule is HIGH, +15 because the account is privileged, −10
because confidence is low"* can.

Factors are summed and then clamped to 0–100. Nothing else happens.

| Score | Band |
|---|---|
| 0–29 | low |
| 30–59 | medium |
| 60–84 | high |
| 85–100 | critical |

## The factors

| Factor | Points | When it applies |
|---|---|---|
| `rule_severity` | 20 / 40 / 65 / 85 | The base score: the **most severe** rule that fired |
| `corroboration` | +8 each, cap +24 | Independent rules agreeing on the same activity |
| `detection_confidence` | +5 / −10 | The most confident rule was high / nothing above low |
| `privileged_account` | +15 | The account is on the privileged list or matches a pattern |
| `critical_host` | +15 | The host is on the critical list or matches a pattern |
| `deception_signal` | +20 | A decoy credential was accessed |
| `external_source` | +5 | The activity came from outside the estate |
| `external_indicators` | +3 each, cap +9 | Breadth of external infrastructure touched |
| `out_of_hours` | +5 | Outside the configured working hours |
| `repeat_activity` | +10 each, cap +20 | The host already has recent alerts |

### Three decisions worth explaining

**The base is the worst rule, not the sum.** Five LOW rules firing is five
low-severity observations, not a CRITICAL alert. The *number* of rules is
reflected by `corroboration`, which is a smaller and separately visible
contribution.

**The same rule twice does not corroborate.** Repetition of one rule is one
rule being noisy. Corroboration counts *distinct* rule IDs, because two
independent detections reaching the same activity is genuine evidence and the
same detection twice is not.

**Low confidence subtracts.** A rule that admits in its own definition that it
is a heuristic — `SF-0014`, high-entropy command lines — should not carry the
same weight as one that does not. This is the mechanism that lets a heuristic
exist in the rule set without inflating everything it touches.

## Environment context

The engine needs to know things ATT&CK cannot tell it. The same encoded
PowerShell command deserves a different response on a developer laptop and on a
domain controller, and the only thing that can know the difference is a list
somebody maintains.

`data/context/environment.yaml` is that list:

```yaml
critical_hosts: [SRV-FILE-01, SRV-DB-01]
critical_host_patterns: ["dc-*", "srv-*", "*-prod-*"]
privileged_accounts: [administrator, root]
privileged_account_patterns: ["adm-*", "*-admin", "svc-*"]
business_hours: {enabled: true, start_hour: 8, end_hour: 18, workdays: [monday, ...]}
```

Every entry that influences a score appears **by name** in the breakdown —
`svc-helper matches the privileged account pattern 'svc-*'` — so an analyst can
see why a score was raised and go and check whether that is still true.

A missing context file degrades rather than failing: scoring keeps working and
simply stops applying the factors it has no basis for, which is the correct
behaviour when nobody has told it anything about this estate.

## The AI cannot reach this

`SeverityEngine.score` takes detections, events, indicators and a count of
prior alerts. There is no parameter through which a model's opinion could
arrive, and no code path from `app/ai` into this module.

Three tests enforce it: every factor name must come from the engine's own
`FACTOR_NAMES` vocabulary, the `score` signature must contain no AI parameter,
and no factor name may begin with `ai`. On top of that, `Alert.severity` is an
`AlertSeverity` — a structured object — so the bare `Severity` enum that
`AIAnalysis.suggested_severity` holds is the wrong type to assign there and
fails validation.

## The pipeline

```
enrich (indicators) -> detect (rules) -> map (ATT&CK) -> score -> alert
```

One alert per event, carrying every rule that fired on it. That is the natural
unit before correlation: an analyst opens an event and asks "what is wrong
here?", and the answer is all of it at once rather than one notification per
rule. Grouping *alerts* into incidents is Stage 9 and a different question.

### Triage is idempotent, and getting that right needed a schema change

"Has this event been triaged?" is not the same question as "is this event the
primary event of an alert". A threshold rule anchors its detection on the last
event of a burst, so the other seven authentication failures have no alert of
their own — and under the naive check they looked untouched and were
re-evaluated on every run, producing a **duplicate brute-force alert each
time**.

Schema version 4 adds `events.triaged_at`, and the pipeline marks every event
it processed rather than only the ones that became alerts. It is the first
migration `create_all` cannot perform, because it alters an existing table.

## Using it

```bash
sentinelflow triage             # process stored events and create alerts
sentinelflow triage --dry-run   # score and report, store nothing
sentinelflow alerts             # the queue
sentinelflow alerts --open --severity high
sentinelflow alert 20ea         # one alert in full, by id prefix
```
