# MITRE ATT&CK Integration

## The problem this solves

Attaching technique IDs to alerts is the easiest thing in security tooling to
fake. It costs nothing, it makes a product look rigorous, and almost nobody
checks. The first time an analyst does check one and finds it hollow, they stop
trusting every other mapping on the page — and the feature becomes worse than
useless, because it has consumed attention and returned noise.

SentinelFlow therefore enforces two rules, in code rather than in
documentation.

## Rule 1: a mapping must state why it applies

`MitreMapping.reason` is mandatory and must be at least ten characters. A
mapping without one **cannot be constructed** — it fails Pydantic validation.

The reason is built from the evidence, not written by hand:

```
Rule SF-0006 (Account added to a privileged group) matched on WIN-LAB-01
for svc-helper: raw_event.GroupName is a privileged group -> Administrators
```

It names the rule, the host, the account, and the field values that satisfied
the rule's conditions. "Why is T1098 on this alert?" always has an answer, and
the answer does not require opening the rule file.

## Rule 2: a technique that cannot be named is not mapped

SentinelFlow will not render a bare `T1234`. An identifier absent from the
catalogue is refused, counted, and reported, so the gap is visible and fixable
rather than papered over with something that looks authoritative.

This is enforced at three levels:

| Layer | Control |
|---|---|
| Rule loading | `sentinelflow rules --validate` fails if any rule references a technique the catalogue cannot resolve |
| Mapping | `MitreMapper` skips unknown identifiers and records them in `unknown_techniques` |
| Database | `mitre_mappings.technique_id` is a foreign key into `mitre_techniques` |

## The catalogue is local

A curated subset of the Enterprise matrix ships in
`data/mitre/techniques.json` — 30 techniques and all 14 tactics, covering every
technique the rules reference plus the neighbours a triage tool tends to need.

It is offline on purpose. SentinelFlow makes no network call, and a technique
name should not depend on whether `attack.mitre.org` is reachable at three in
the morning. The file records its own provenance: source, version, retrieval
date, and attribution.

> MITRE ATT&CK® is a registered trademark of The MITRE Corporation. Technique
> identifiers, names and tactic assignments come from the public Enterprise
> matrix. The one-line summaries in the file are written for this project
> rather than copied.

A missing or broken catalogue degrades rather than crashing: detections still
fire, severity is unaffected, and `sentinelflow doctor` reports the gap.

## Sub-technique fallback

`T1059.009` is genuinely a kind of `T1059`. If a rule references a
sub-technique the catalogue does not carry, the mapper resolves to the parent
and **says so in the reason**:

```
... (rule referenced T1059.009; mapped to parent technique T1059)
```

That is accurate rather than invented. Dropping the mapping entirely would
discard information the rule author legitimately had; silently pretending the
sub-technique was known would not.

## Restraint in the rule set

`SF-0010` (newly exposed network service) maps to **no** technique.

ATT&CK describes adversary behaviour. Exposing a service is a configuration
change. `T1133 External Remote Services` covers an adversary *using* such a
service to get in — which the evidence does not show. The rule file says so in
a comment, and a test asserts the mapping list stays empty.

## Coverage is a map, not a score

```bash
sentinelflow mitre --coverage
```

```
Initial Access          2    SF-0002, SF-0007
Execution               3    SF-0003, SF-0007, SF-0015
Persistence             5    SF-0002, SF-0005, SF-0006, SF-0013, SF-0015
Credential Access       2    SF-0001, SF-0009
Discovery               0    no coverage
Lateral Movement        0    no coverage
Exfiltration            0    no coverage
```

The zeroes are the useful part. Every real estate has gaps, and a tool that
presents coverage as a percentage encourages people to chase the number rather
than close the gap. Naming what the rules cannot see is more honest and more
actionable than a score of 64%.

## What the demo scenario produces

Nine detections map to nine techniques across seven tactics:

| Technique | Name | From |
|---|---|---|
| T1110 | Brute Force | SF-0001 |
| T1078 | Valid Accounts | SF-0002 |
| T1059.001 | PowerShell | SF-0003 |
| T1027 | Obfuscated Files or Information | SF-0003 |
| T1036 | Masquerading | SF-0008 |
| T1555 | Credentials from Password Stores | SF-0009 |
| T1071.001 | Web Protocols | SF-0011 |
| T1136.001 | Create Account: Local Account | SF-0005 |
| T1098 | Account Manipulation | SF-0006 |

The same technique reached by two independent rules is kept twice rather than
collapsed — two rules agreeing is corroboration, and hiding that would discard
the signal.

## Using it

```bash
sentinelflow mitre                       # the catalogue
sentinelflow mitre --technique T1059.001 # one technique in detail
sentinelflow mitre --coverage            # tactic coverage by rule
sentinelflow mitre --sync                # mirror into the database
sentinelflow rules --validate            # fails if a reference cannot resolve
sentinelflow detect                      # detections plus the techniques they map to
```
