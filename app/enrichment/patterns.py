"""Patterns and allow-lists for indicator extraction.

Extraction is mostly an exercise in *not* matching things. A naive IPv4 regex
finds version numbers, a naive domain regex finds every filename, and a naive
hash regex finds any run of hex. An analyst who is shown ``update.exe`` as a
domain stops trusting the indicator panel, and a tool whose indicator panel is
not trusted is worse than one without it.

So every pattern here is paired with a rejection rule:

* **IP addresses** are matched, then parsed by :mod:`ipaddress`. Lookarounds
  reject a match embedded in a longer dotted-numeric run, which is what a
  version string like ``10.0.19041.1234`` looks like.
* **Domains** must end in a TLD from the allow-list below. That one rule
  removes ``config.json``, ``script.ps1`` and ``update.exe`` without a special
  case for each.
* **Hashes** must be exactly 32, 40 or 64 hex characters with no hex either
  side, so a longer blob does not yield a spurious digest.
* **POSIX paths** must begin with a real system directory. Bare ``/a/b``
  matches far too much — URL paths, dates, arithmetic in a command line.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"

#: IPv4, guarded on both sides against a longer dotted-numeric sequence.
IPV4_RE = re.compile(rf"(?<![\d.])(?:{_OCTET}\.){{3}}{_OCTET}(?![\d.]*\d)")

#: Permissive IPv6 candidate. Real validation is done by ipaddress, which
#: rejects the timestamps and MAC addresses this happily matches.
IPV6_RE = re.compile(
    r"(?<![:.\w])"
    r"(?:[A-Fa-f0-9]{1,4}:){2,7}(?::|[A-Fa-f0-9]{1,4})"
    r"(?:(?:\d{1,3}\.){3}\d{1,3})?"
    r"(?![:\w])"
)

URL_RE = re.compile(r"\b(?:https?|ftps?|sftp|wss?)://[^\s<>\"'`\])}|]+", re.IGNORECASE)

DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![\w-])"
)

EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![\w-])"
)

# ---------------------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------------------
SHA256_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])")
SHA1_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])")
MD5_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])")

# ---------------------------------------------------------------------------
# Files and processes
# ---------------------------------------------------------------------------
WINDOWS_PATH_RE = re.compile(
    r"(?:[A-Za-z]:\\|\\\\[A-Za-z0-9_.-]+\\)(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n\s]+"
)

#: Only paths rooted in a real system directory. ``/a/b`` matches too much.
POSIX_PATH_RE = re.compile(
    r"(?<![\w.])/(?:etc|tmp|var|usr|opt|home|root|bin|sbin|dev|proc|srv|mnt|media|Users|Library|Applications)"
    r"(?:/[\w.@+-]+)+"
)

#: Extensions worth recording when they appear in free text.
EXECUTABLE_EXTENSIONS = (
    "exe",
    "dll",
    "sys",
    "ps1",
    "psm1",
    "bat",
    "cmd",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsf",
    "hta",
    "scr",
    "com",
    "msi",
    "msp",
    "jar",
    "py",
    "sh",
    "lnk",
    "scf",
)

PROCESS_NAME_RE = re.compile(
    r"(?<![\w.\\/-])[\w.+-]{1,60}\.(?:" + "|".join(EXECUTABLE_EXTENSIONS) + r")(?![\w])",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# TLD allow-list
# ---------------------------------------------------------------------------
#: A domain candidate is only accepted if its final label appears here.
#:
#: Two deliberate omissions: ``zip`` and ``mov``. Both are real TLDs and both
#: are far more commonly file extensions in a security log. Treating
#: ``payload.zip`` as a domain would be wrong far more often than right, and a
#: missed indicator is recoverable where a wrong one erodes trust.
#:
#: RFC 2606 reserved names (``example``, ``test``, ``invalid``, ``localhost``)
#: are included, because synthetic and lab data legitimately uses them.
VALID_TLDS: frozenset[str] = frozenset(
    """
    com org net int edu gov mil arpa info biz name pro coop museum aero jobs
    mobi travel post asia cat tel xxx
    app dev cloud io ai co me tv cc ws ly sh gg to
    online site website space store shop tech xyz top club live news blog
    email network systems solutions services digital agency media group
    center company careers finance software security support tools zone
    ac ad ae af ag al am ao aq ar at au az ba bd be bf bg bh bi bj bn bo br bs
    bt bw by bz ca cd cf cg ch ci cl cm cn cr cu cv cy cz de dj dk dm do dz ec
    ee eg er es et eu fi fj fm fo fr ga gd ge gh gi gl gm gn gp gq gr gt gw gy
    hk hn hr ht hu id ie il im in iq ir is it je jm jo jp ke kg kh ki km kn kp
    kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md mg mk ml mm mn mo mq
    mr mt mu mv mw mx my mz na ne ng ni nl no np nr nu nz om pa pe pf pg ph pk
    pl pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg si sk sl sm sn so sr
    ss st sv sy sz td tg th tj tm tn tr tt tw tz ua ug uk us uy uz va vc ve vn
    vu ye za zm zw
    example test invalid localhost local internal lan corp
    """.split()  # noqa: SIM905 - a whitespace block stays readable and editable
)


def has_valid_tld(domain: str) -> bool:
    """Whether a domain candidate ends in a recognised TLD."""
    label = domain.rsplit(".", 1)[-1].lower()
    return label in VALID_TLDS
