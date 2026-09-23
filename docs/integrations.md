# Integrations

SentinelFlow accepts events from any source that can produce JSON or CSV. This
document is the contract: what each adapter expects, and what it does with
fields it does not recognise.

Two rules hold for every source:

* **Unrecognised fields are never fatal.** They are preserved in `raw_event`
  and shown to the analyst. A producer that adds a field does not break
  ingestion.
* **Unrecognised event categories are never dropped.** The canonical
  `event_type` falls back to `other`, and the original value is kept in
  `event_type_raw`.

## Choosing an adapter

```bash
sentinelflow adapters                                  # list them
sentinelflow import events.json                        # auto-detect
sentinelflow import events.json --source sysmon        # explicit
```

Auto-detection inspects the first readable record. An explicit `--source`
always wins: guessing wrong silently mislabels evidence, which is worse than
refusing to guess. If nothing matches and no source is given, the import is
rejected with a list of the available adapters rather than a guess.

## Sibling projects

These two adapters exist so **DriftWatch** and **GhostCredential** can submit
alerts to SentinelFlow. Neither project is required; the contracts below are
what SentinelFlow accepts.

### DriftWatch — network exposure changes

`POST /api/v1/events` with `"source": "driftwatch"`, an upload to `POST /api/v1/events/import`, or `sentinelflow import drift.json --source driftwatch`.

```json
{
  "detected_at": "2026-09-23T13:10:00Z",
  "asset": "WIN-LAB-01",
  "asset_ip": "10.0.0.5",
  "change_type": "service_exposed",
  "port": 3389,
  "protocol": "tcp",
  "service": "rdp",
  "previous_state": "closed",
  "current_state": "open",
  "severity": "medium"
}
```

| Field | Required | Maps to |
|---|---|---|
| `detected_at` | yes | `timestamp` |
| `asset` / `hostname` | no | `hostname` |
| `asset_ip` | no | `dst_ip` |
| `change_type` | no | `event_type_raw`, and a tag |
| `port`, `protocol` | no | `dst_port`, `protocol` |
| `severity` | no | `source_severity` — a claim, never the verdict |

Recognised `change_type` values: `service_exposed`, `port_opened`,
`port_closed`, `service_removed`, `config_drift`, `tls_downgrade`,
`firewall_rule_changed`. Others are accepted and preserved.

All events become `event_type: network_exposure_change`. A newly exposed
service is a change worth correlating, not a finding on its own.

### GhostCredential — decoy credential access

```json
{
  "triggered_at": "2026-09-23T14:05:00Z",
  "decoy_id": "decoy-svc-backup",
  "decoy_type": "service_account",
  "accessed_by": "LAB\\lab-user",
  "source_ip": "10.0.0.5",
  "hostname": "WIN-LAB-01",
  "access_method": "credential_store_read",
  "process_name": "powershell.exe"
}
```

`decoy_id` (or `decoy_name`) is **required** — an unattributable decoy alert is
not useful evidence. Events become `event_type: decoy_credential_access` with
`source_confidence: high`, because nothing legitimate touches a decoy.

That is still a claim recorded in a field named as a claim. It feeds the
deterministic severity engine as a strong signal; it does not bypass it. A
decoy can be tripped by a misconfigured backup agent or by the blue team's own
testing, which is exactly why a human confirms.

## Windows sources

### Sysmon

Expects `UtcTime` and `EventID`. Mapped IDs: 1 (process creation), 3 (network
connection), 5 (process termination), 11/15 (file creation), 12–14 (registry),
22 (DNS query), 23/26 (file deletion).

`Image` and `ParentImage` are reduced to basenames. `Hashes` accepts
`SHA256=...,MD5=...`; the strongest digest wins, because a collision-prone one
makes a poor correlation key. Hex process IDs (`0x10a4`) are parsed.

### Windows Security

Expects `TimeCreated` and `EventID`. Mapped IDs include 4624/4625 (logon
success/failure), 4688 (process creation), 4720 (account created), 4728/4732/4756
(group membership), 4698 (scheduled task), 7045 (service installed), 1102 (log
cleared).

`TargetUserName` is preferred over `SubjectUserName`: for a logon or an account
change, the account acted upon is the story. Windows' `-` placeholder is treated
as absent rather than stored as a literal hyphen.

## Firewall and generic flows

Vendor-neutral. Accepts common spellings — `src_ip` / `srcip` / `source_ip` /
`src` and the destination equivalents — plus `action`, `protocol` and ports.
Blocking actions (`deny`, `drop`, `reject`, `block`) add a `blocked` tag. CSV
delimiters are detected, so semicolon-separated exports work unchanged.

## Canonical

For producers written against SentinelFlow directly, and for the REST API.
Uses the field names in [data-model.md](data-model.md). Only `timestamp` and
`source` are required.

## What happens to bad records

Nothing is silently discarded. Every input becomes either a stored event or a
stored rejection with a reason, so the counts always add up — an analyst can
tell the difference between "nothing happened on that host" and "the import
dropped 400 lines".

```bash
sentinelflow import data/samples/malformed.json --source canonical
sentinelflow rejections
```

| Reason | Meaning |
|---|---|
| `malformed_json` / `malformed_csv` | The record could not be parsed |
| `not_an_object` | Valid JSON, but not an object |
| `schema_validation` | A field failed validation (bad IP, hash, URL, timestamp) |
| `adapter_error` | The adapter could not translate it (usually a missing timestamp) |
| `unknown_source` | No adapter recognised the format |
| `nesting_too_deep` | JSON nested beyond the limit — a denial-of-service guard |
| `limit_exceeded` | The import hit `SENTINELFLOW_MAX_EVENTS_PER_IMPORT` |
| `empty_record` | The record had no usable fields |

## Re-importing

Imports are idempotent by content hash: running the same file twice does
nothing the second time. Pass `--force` to import it anyway.

Individual events are **not** deduplicated, deliberately. Two identical failed
logons a second apart are two failures, and collapsing them would quietly break
every rule that counts repetitions — which is most of the interesting ones.

## Writing a new adapter

1. Subclass `SourceAdapter` in `app/ingestion/adapters/`.
2. Set `name`, `aliases` and `description`.
3. Implement `normalise()`, using `RecordView` for case-insensitive lookup, and
   `self.build()` so the original record is preserved.
4. Implement `matches()` if auto-detection should recognise the format.
5. Register it in `ADAPTERS` and add tests.

Nothing downstream changes. That is the point of having a canonical schema.
