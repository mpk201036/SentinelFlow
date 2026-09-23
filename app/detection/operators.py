"""Condition operators for the detection language.

Every operator is a plain function over a value and an expected argument. That
is the whole extension point: a rule author picks an operator by name, and the
engine never evaluates anything the rule file supplies as code.

**No rule content is ever executed.** There is no ``eval``, no lambda, no
import hook. The only thing a rule can do is name an operator from this module
and hand it data. A malicious rule file is still a serious problem — rule files
are trusted content, like code — but it cannot become arbitrary execution by
accident, which is what a "just use eval, it's only config" design does.

Regular expressions are compiled when rules load, not when an alert is being
triaged, so a broken pattern fails at startup with the file name attached
rather than midway through an investigation.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from collections.abc import Callable, Sequence
from typing import Any

#: Longest regular expression accepted from a rule file. Rules are trusted
#: content, but an accidental 10 KB pattern is still worth refusing.
MAX_PATTERN_LENGTH = 1_024

#: Longest value any operator will inspect. Field values are already capped by
#: the event schema; this is a second bound in case that changes.
MAX_VALUE_LENGTH = 32_768


def _as_text(value: Any) -> str:
    return value if isinstance(value, str) else str(value)


def _texts(value: Any) -> list[str]:
    """Flatten a field value into the strings an operator should test.

    List fields such as ``tags`` are tested element by element, so
    ``tags contains deception`` means "one of the tags contains it", which is
    what a rule author expects.
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [_as_text(item)[:MAX_VALUE_LENGTH] for item in value]
    return [_as_text(value)[:MAX_VALUE_LENGTH]]


def _expected(argument: Any) -> list[str]:
    if isinstance(argument, (list, tuple, set)):
        return [_as_text(item) for item in argument]
    return [_as_text(argument)]


# ---------------------------------------------------------------------------
# String operators
# ---------------------------------------------------------------------------
def op_equals(value: Any, argument: Any, *, ignore_case: bool = True) -> bool:
    """True when the field equals any of the expected values."""
    actual = _texts(value)
    wanted = _expected(argument)
    if ignore_case:
        actual = [item.lower() for item in actual]
        wanted = [item.lower() for item in wanted]
    return any(item in wanted for item in actual)


def op_contains(value: Any, argument: Any, *, ignore_case: bool = True) -> bool:
    """True when the field contains any of the expected substrings."""
    actual = _texts(value)
    wanted = _expected(argument)
    if ignore_case:
        actual = [item.lower() for item in actual]
        wanted = [item.lower() for item in wanted]
    return any(needle in haystack for haystack in actual for needle in wanted)


def op_contains_all(value: Any, argument: Any, *, ignore_case: bool = True) -> bool:
    """True when the field contains every expected substring."""
    actual = _texts(value)
    wanted = _expected(argument)
    if ignore_case:
        actual = [item.lower() for item in actual]
        wanted = [item.lower() for item in wanted]
    return all(any(needle in haystack for haystack in actual) for needle in wanted)


def op_startswith(value: Any, argument: Any, *, ignore_case: bool = True) -> bool:
    actual = _texts(value)
    wanted = _expected(argument)
    if ignore_case:
        actual = [item.lower() for item in actual]
        wanted = [item.lower() for item in wanted]
    return any(item.startswith(tuple(wanted)) for item in actual if wanted)


def op_endswith(value: Any, argument: Any, *, ignore_case: bool = True) -> bool:
    actual = _texts(value)
    wanted = _expected(argument)
    if ignore_case:
        actual = [item.lower() for item in actual]
        wanted = [item.lower() for item in wanted]
    return any(item.endswith(tuple(wanted)) for item in actual if wanted)


def op_regex(value: Any, argument: Any, *, ignore_case: bool = True) -> bool:
    """True when any compiled pattern matches. Patterns compile at load time."""
    patterns = argument if isinstance(argument, list) else [argument]
    compiled = [compile_pattern(p, ignore_case=ignore_case) for p in patterns]
    return any(pattern.search(item) for item in _texts(value) for pattern in compiled)


# ---------------------------------------------------------------------------
# Presence and size
# ---------------------------------------------------------------------------
def op_exists(value: Any, argument: Any = True, **_: Any) -> bool:
    """True when the field has a usable value. ``argument`` may invert it."""
    present = value is not None and value != "" and value != []
    return present if bool(argument) else not present


def op_length_gt(value: Any, argument: Any, **_: Any) -> bool:
    """True when the field is longer than a threshold.

    Very long command lines are a weak but real signal, and cheap to test.
    """
    limit = int(argument)
    return any(len(item) > limit for item in _texts(value))


def op_entropy_gt(value: Any, argument: Any, **_: Any) -> bool:
    """True when Shannon entropy exceeds a threshold.

    Encoded or packed blobs sit around 4.5-6 bits per character where English
    text and normal paths sit nearer 3.5. It is a heuristic, which is why rules
    that use it pair it with something else.
    """
    limit = float(argument)
    return any(shannon_entropy(item) > limit for item in _texts(value))


def shannon_entropy(text: str) -> float:
    """Shannon entropy of a string, in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


# ---------------------------------------------------------------------------
# Numeric and network
# ---------------------------------------------------------------------------
def _numbers(value: Any) -> list[float]:
    numbers: list[float] = []
    for item in _texts(value):
        try:
            numbers.append(float(item))
        except (TypeError, ValueError):
            continue
    return numbers


def op_gt(value: Any, argument: Any, **_: Any) -> bool:
    return any(number > float(argument) for number in _numbers(value))


def op_gte(value: Any, argument: Any, **_: Any) -> bool:
    return any(number >= float(argument) for number in _numbers(value))


def op_lt(value: Any, argument: Any, **_: Any) -> bool:
    return any(number < float(argument) for number in _numbers(value))


def op_lte(value: Any, argument: Any, **_: Any) -> bool:
    return any(number <= float(argument) for number in _numbers(value))


def op_cidr(value: Any, argument: Any, **_: Any) -> bool:
    """True when the field is an address inside any listed network."""
    networks = []
    for item in _expected(argument):
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    for item in _texts(value):
        try:
            address = ipaddress.ip_address(item)
        except ValueError:
            continue
        if any(address in network for network in networks):
            return True
    return False


def op_is_private(value: Any, argument: Any = True, **_: Any) -> bool:
    """True when the field is (or is not) an address on an internal network."""
    from app.models.indicator import Indicator

    wanted = bool(argument)
    for item in _texts(value):
        try:
            indicator = Indicator(indicator_type=_ip_type(item), value=item)
        except ValueError:
            continue
        if indicator.is_internal is wanted:
            return True
    return False


def _ip_type(value: str) -> Any:
    from app.models.enums import IndicatorType

    address = ipaddress.ip_address(value)
    return IndicatorType.IPV6 if isinstance(address, ipaddress.IPv6Address) else IndicatorType.IPV4


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
Operator = Callable[..., bool]

OPERATORS: dict[str, Operator] = {
    "equals": op_equals,
    "not_equals": lambda value, argument, **kw: not op_equals(value, argument, **kw),
    "contains": op_contains,
    "not_contains": lambda value, argument, **kw: not op_contains(value, argument, **kw),
    "contains_all": op_contains_all,
    "startswith": op_startswith,
    "endswith": op_endswith,
    "regex": op_regex,
    "not_regex": lambda value, argument, **kw: not op_regex(value, argument, **kw),
    "exists": op_exists,
    "length_gt": op_length_gt,
    "entropy_gt": op_entropy_gt,
    "gt": op_gt,
    "gte": op_gte,
    "lt": op_lt,
    "lte": op_lte,
    "cidr": op_cidr,
    "not_cidr": lambda value, argument, **kw: not op_cidr(value, argument, **kw),
    "is_private": op_is_private,
}

#: Operators whose argument is a pattern that must compile at load time.
REGEX_OPERATORS = frozenset({"regex", "not_regex"})

#: Operators taking a numeric argument.
NUMERIC_OPERATORS = frozenset({"gt", "gte", "lt", "lte", "length_gt", "entropy_gt"})


def compile_pattern(pattern: Any, *, ignore_case: bool = True) -> re.Pattern[str]:
    """Compile a rule-supplied regular expression, with a size limit.

    ``re.error`` is translated into ``ValueError`` deliberately. It subclasses
    ``Exception``, not ``ValueError``, so Pydantic would let it escape
    validation unwrapped and the rule loader would not catch it — one malformed
    pattern would take down the entire rule load instead of being reported as
    one bad file.
    """
    text = _as_text(pattern)
    if len(text) > MAX_PATTERN_LENGTH:
        raise ValueError(f"pattern exceeds {MAX_PATTERN_LENGTH} characters")
    try:
        return re.compile(text, re.IGNORECASE if ignore_case else 0)
    except re.error as exc:
        raise ValueError(f"invalid regular expression {text!r}: {exc}") from exc


def available_operators() -> Sequence[str]:
    return sorted(OPERATORS)
