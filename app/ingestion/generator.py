"""Synthetic event generation for demonstration and testing.

Everything here is fabricated and harmless: RFC 5737 documentation addresses,
``example`` domains, lab hostnames, and no credential material of any kind. The
encoded PowerShell payload decodes to a comment.

The generator emits records in each source's **native** shape rather than the
canonical one, so a demo import exercises the adapters exactly as a real import
would. A demo that bypassed normalisation would prove nothing.
"""

from __future__ import annotations

import base64
import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

#: RFC 5737 TEST-NET-1: reserved for documentation, never routable.
EXTERNAL_IP = "192.0.2.77"
WORKSTATION_IP = "10.0.0.5"
LAB_HOST = "WIN-LAB-01"
LAB_USER = "lab-user"
DOMAIN = "LAB"

#: Decodes to "# SentinelFlow demo payload - harmless".
DEMO_ENCODED_COMMAND = base64.b64encode(
    "# SentinelFlow demo payload - harmless".encode("utf-16-le")
).decode("ascii")


@dataclass(frozen=True)
class GeneratedRecord:
    """One synthetic record, tagged with the adapter that should handle it."""

    adapter: str
    record: dict[str, Any]


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sysmon_time(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def generate_demo_scenario(base_time: datetime | None = None) -> list[GeneratedRecord]:
    """The end-to-end demonstration sequence.

    A credential attack that succeeds, followed by hands-on-keyboard activity
    and persistence:

    1. repeated failed logons from one external address
    2. a successful logon for the same account
    3. encoded PowerShell, spawned from cmd.exe
    4. an outbound connection and a file written to a temp directory
    5. a decoy credential touched
    6. a new account created and added to Administrators
    7. a newly exposed service on the same host

    None of these steps is conclusive alone. Together they are what correlation
    in Stage 9 is meant to surface — and what an analyst, not the tool, decides
    about.
    """
    start = (base_time or datetime.now(UTC) - timedelta(hours=1)).astimezone(UTC)
    records: list[GeneratedRecord] = []

    # 1. Eight failed logons over four minutes.
    for attempt in range(8):
        moment = start + timedelta(seconds=30 * attempt)
        records.append(
            GeneratedRecord(
                "windows_security",
                {
                    "TimeCreated": _iso(moment),
                    "EventID": 4625,
                    "Computer": LAB_HOST,
                    "TargetUserName": LAB_USER,
                    "SubjectUserName": "-",
                    "IpAddress": EXTERNAL_IP,
                    "IpPort": 49000 + attempt,
                    "LogonType": 3,
                    "Status": "0xC000006D",
                    "Message": "An account failed to log on.",
                },
            )
        )

    # 2. The ninth attempt succeeds.
    logon_time = start + timedelta(minutes=4, seconds=30)
    records.append(
        GeneratedRecord(
            "windows_security",
            {
                "TimeCreated": _iso(logon_time),
                "EventID": 4624,
                "Computer": LAB_HOST,
                "TargetUserName": LAB_USER,
                "IpAddress": EXTERNAL_IP,
                "IpPort": 49008,
                "LogonType": 3,
                "Message": "An account was successfully logged on.",
            },
        )
    )

    # 3. Encoded PowerShell, spawned by cmd.exe.
    powershell_time = logon_time + timedelta(minutes=2)
    records.append(
        GeneratedRecord(
            "sysmon",
            {
                "UtcTime": _sysmon_time(powershell_time),
                "EventID": 1,
                "Computer": LAB_HOST,
                "User": f"{DOMAIN}\\{LAB_USER}",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": f"powershell.exe -nop -w hidden -enc {DEMO_ENCODED_COMMAND}",
                "ParentCommandLine": "cmd.exe /c start",
                "ProcessId": 4242,
                "ParentProcessId": 1180,
                "Hashes": f"SHA256={'a1' * 32}",
            },
        )
    )

    # 4a. Outbound connection to the same external address.
    connect_time = powershell_time + timedelta(seconds=20)
    records.append(
        GeneratedRecord(
            "sysmon",
            {
                "UtcTime": _sysmon_time(connect_time),
                "EventID": 3,
                "Computer": LAB_HOST,
                "User": f"{DOMAIN}\\{LAB_USER}",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "SourceIp": WORKSTATION_IP,
                "SourcePort": 51544,
                "DestinationIp": EXTERNAL_IP,
                "DestinationPort": 443,
                "DestinationHostname": "updates.example",
                "Protocol": "tcp",
            },
        )
    )

    # 4b. A file written to a temp directory.
    write_time = connect_time + timedelta(seconds=15)
    records.append(
        GeneratedRecord(
            "sysmon",
            {
                "UtcTime": _sysmon_time(write_time),
                "EventID": 11,
                "Computer": LAB_HOST,
                "User": f"{DOMAIN}\\{LAB_USER}",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "TargetFilename": "C:\\Users\\lab-user\\AppData\\Local\\Temp\\update.exe",
                "Hashes": f"SHA256={'b2' * 32}",
            },
        )
    )

    # 5. A decoy credential is touched.
    decoy_time = write_time + timedelta(minutes=1)
    records.append(
        GeneratedRecord(
            "ghostcredential",
            {
                "triggered_at": _iso(decoy_time),
                "decoy_id": "decoy-svc-backup",
                "decoy_type": "service_account",
                "accessed_by": f"{DOMAIN}\\{LAB_USER}",
                "source_ip": WORKSTATION_IP,
                "hostname": LAB_HOST,
                "access_method": "credential_store_read",
                "process_name": "powershell.exe",
            },
        )
    )

    # 6. A new account, then privilege.
    account_time = decoy_time + timedelta(minutes=2)
    records.append(
        GeneratedRecord(
            "windows_security",
            {
                "TimeCreated": _iso(account_time),
                "EventID": 4720,
                "Computer": LAB_HOST,
                "TargetUserName": "svc-helper",
                "SubjectUserName": LAB_USER,
                "Message": "A user account was created.",
            },
        )
    )
    records.append(
        GeneratedRecord(
            "windows_security",
            {
                "TimeCreated": _iso(account_time + timedelta(seconds=40)),
                "EventID": 4732,
                "Computer": LAB_HOST,
                "TargetUserName": "svc-helper",
                "SubjectUserName": LAB_USER,
                "GroupName": "Administrators",
                "Message": "A member was added to a security-enabled local group.",
            },
        )
    )

    # 7. A newly exposed service on the same host.
    records.append(
        GeneratedRecord(
            "driftwatch",
            {
                "detected_at": _iso(account_time + timedelta(minutes=3)),
                "asset": LAB_HOST,
                "asset_ip": WORKSTATION_IP,
                "change_type": "service_exposed",
                "port": 3389,
                "protocol": "tcp",
                "service": "rdp",
                "previous_state": "closed",
                "current_state": "open",
                "severity": "medium",
            },
        )
    )
    return records


def generate_normal_activity(
    count: int = 40, *, base_time: datetime | None = None, seed: int = 1337
) -> list[GeneratedRecord]:
    """Benign background activity.

    Without this, every event in the database is suspicious and the dashboard
    gives a badly misleading impression of what triage is like.
    """
    # Seeded and reproducible on purpose: the same seed must produce the same
    # dataset so demos and tests are deterministic. Not used for anything
    # security-sensitive, where secrets.SystemRandom would be required.
    rng = random.Random(seed)  # noqa: S311
    start = (base_time or datetime.now(UTC) - timedelta(hours=6)).astimezone(UTC)

    hosts = ["WIN-LAB-01", "WIN-LAB-02", "WIN-DEV-07", "SRV-FILE-01"]
    users = ["lab-user", "j.taylor", "m.okafor", "build-agent"]
    benign = [
        ("explorer.exe", "userinit.exe", "C:\\Windows\\explorer.exe"),
        ("chrome.exe", "explorer.exe", "chrome.exe --profile-directory=Default"),
        ("outlook.exe", "explorer.exe", "outlook.exe /recycle"),
        ("teams.exe", "explorer.exe", "teams.exe --startup"),
        ("git.exe", "code.exe", "git.exe fetch --all"),
    ]
    lookups = ["updates.example", "docs.example", "mail.example", "cdn.example"]

    records: list[GeneratedRecord] = []
    for index in range(count):
        moment = start + timedelta(seconds=rng.randint(0, 6 * 3600))
        host = rng.choice(hosts)
        user = rng.choice(users)
        roll = rng.random()

        if roll < 0.55:
            image, parent, command = rng.choice(benign)
            records.append(
                GeneratedRecord(
                    "sysmon",
                    {
                        "UtcTime": _sysmon_time(moment),
                        "EventID": 1,
                        "Computer": host,
                        "User": f"{DOMAIN}\\{user}",
                        "Image": f"C:\\Program Files\\{image}",
                        "ParentImage": f"C:\\Windows\\{parent}",
                        "CommandLine": command,
                        "ProcessId": 2000 + index,
                        "ParentProcessId": 1000 + index,
                    },
                )
            )
        elif roll < 0.8:
            records.append(
                GeneratedRecord(
                    "windows_security",
                    {
                        "TimeCreated": _iso(moment),
                        "EventID": 4624,
                        "Computer": host,
                        "TargetUserName": user,
                        "IpAddress": f"10.0.0.{rng.randint(10, 60)}",
                        "LogonType": 2,
                        "Message": "An account was successfully logged on.",
                    },
                )
            )
        else:
            records.append(
                GeneratedRecord(
                    "sysmon",
                    {
                        "UtcTime": _sysmon_time(moment),
                        "EventID": 22,
                        "Computer": host,
                        "User": f"{DOMAIN}\\{user}",
                        "Image": "C:\\Program Files\\chrome.exe",
                        "QueryName": rng.choice(lookups),
                    },
                )
            )
    return records


def generate_dataset(
    *, normal_count: int = 40, include_scenario: bool = True, seed: int = 1337
) -> list[GeneratedRecord]:
    """Background noise plus, optionally, the demonstration scenario."""
    records = generate_normal_activity(normal_count, seed=seed)
    if include_scenario:
        records.extend(generate_demo_scenario())
    return records


def group_by_adapter(records: list[GeneratedRecord]) -> dict[str, list[dict[str, Any]]]:
    """Group generated records by the adapter that should normalise them."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in records:
        grouped.setdefault(item.adapter, []).append(item.record)
    return grouped
