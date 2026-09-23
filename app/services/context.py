"""Environment context: what this estate considers important.

The severity engine needs to know things ATT&CK cannot tell it. The same
encoded PowerShell command deserves a different response on a developer laptop
and on a domain controller, and the only thing that can know the difference is
a list somebody maintains.

``data/context/environment.yaml`` is that list. It is deliberately small and
readable, because the alternative — inferring criticality from naming
conventions alone — produces scores nobody can explain or correct.

Every entry that influences a score appears **by name** in the alert's severity
breakdown, so an analyst can see that a score was raised because the host is on
this list, and can go and check whether that is still true.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from fnmatch import fnmatch
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]


@dataclass
class BusinessHours:
    """When activity on this estate is expected."""

    enabled: bool = True
    start_hour: int = 8
    end_hour: int = 18
    workdays: frozenset[int] = field(default_factory=lambda: frozenset({0, 1, 2, 3, 4}))

    def contains(self, moment: datetime) -> bool:
        """Whether a timestamp falls inside working hours, in UTC."""
        if not self.enabled:
            return True
        if moment.weekday() not in self.workdays:
            return False
        return self.start_hour <= moment.hour < self.end_hour


@dataclass
class EnvironmentContext:
    """Facts about this estate, loaded from configuration."""

    critical_hosts: frozenset[str] = frozenset()
    critical_host_patterns: tuple[str, ...] = ()
    privileged_accounts: frozenset[str] = frozenset()
    privileged_account_patterns: tuple[str, ...] = ()
    business_hours: BusinessHours = field(default_factory=BusinessHours)
    errors: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    def critical_host_reason(self, hostname: str | None) -> str | None:
        """Why a host counts as critical, or ``None`` if it does not.

        Returns the reason rather than a boolean so the severity factor can
        quote the specific list entry that applied.
        """
        if not hostname:
            return None
        name = hostname.strip().lower()
        if name in self.critical_hosts:
            return f"{hostname} is listed as a critical host"
        for pattern in self.critical_host_patterns:
            if fnmatch(name, pattern.lower()):
                return f"{hostname} matches the critical host pattern {pattern!r}"
        return None

    def privileged_account_reason(self, username: str | None) -> str | None:
        """Why an account counts as privileged, or ``None`` if it does not."""
        if not username:
            return None
        bare = username.strip().lower()
        for separator in ("\\", "/"):
            if separator in bare:
                bare = bare.rsplit(separator, 1)[-1]
        bare = bare.removesuffix("$")
        if not bare:
            return None
        if bare in self.privileged_accounts:
            return f"{username} is listed as a privileged account"
        for pattern in self.privileged_account_patterns:
            if fnmatch(bare, pattern.lower()):
                return f"{username} matches the privileged account pattern {pattern!r}"
        return None

    def is_out_of_hours(self, moment: datetime | None) -> bool:
        if moment is None or not self.business_hours.enabled:
            return False
        return not self.business_hours.contains(moment)

    def summary(self) -> str:
        return (
            f"{len(self.critical_hosts)} critical hosts, "
            f"{len(self.critical_host_patterns)} host patterns, "
            f"{len(self.privileged_accounts)} privileged accounts, "
            f"{len(self.privileged_account_patterns)} account patterns"
        )


def _string_set(value: Any) -> frozenset[str]:
    if not isinstance(value, list):
        return frozenset()
    return frozenset(str(item).strip().lower() for item in value if str(item).strip())


def _string_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item).strip() for item in value if str(item).strip())


def load_context(path: str | Path | None = None) -> EnvironmentContext:
    """Load the environment context.

    A missing or broken file yields an empty context with the reason recorded.
    Scoring still works: it simply stops applying the factors that depend on
    knowing this estate, which is the correct behaviour when nobody has told it
    anything about this estate.
    """
    target = Path(path) if path is not None else get_settings().context_file
    context = EnvironmentContext()

    if not target.is_file():
        context.errors.append(f"context file not found at {target}")
        logger.info("no environment context at %s - asset factors will not apply", target)
        return context

    try:
        payload = yaml.safe_load(target.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        context.errors.append(f"could not read context: {exc}")
        logger.warning("environment context could not be read: %s", exc)
        return context

    if not isinstance(payload, dict):
        context.errors.append("context file must be a mapping")
        return context

    context.critical_hosts = _string_set(payload.get("critical_hosts"))
    context.critical_host_patterns = _string_tuple(payload.get("critical_host_patterns"))
    context.privileged_accounts = _string_set(payload.get("privileged_accounts"))
    context.privileged_account_patterns = _string_tuple(payload.get("privileged_account_patterns"))

    hours = payload.get("business_hours")
    if isinstance(hours, dict):
        try:
            workdays = frozenset(
                WEEKDAYS.index(str(day).strip().lower())
                for day in hours.get("workdays", [])
                if str(day).strip().lower() in WEEKDAYS
            )
            context.business_hours = BusinessHours(
                enabled=bool(hours.get("enabled", True)),
                start_hour=int(hours.get("start_hour", 8)),
                end_hour=int(hours.get("end_hour", 18)),
                workdays=workdays or frozenset({0, 1, 2, 3, 4}),
            )
        except (TypeError, ValueError) as exc:
            context.errors.append(f"invalid business_hours: {exc}")

    logger.info("loaded environment context: %s", context.summary())
    return context


@lru_cache(maxsize=1)
def get_context() -> EnvironmentContext:
    """Process-wide context, loaded once."""
    return load_context()
