"""Stage 2 — normalisation and sanitisation of untrusted field values."""

from __future__ import annotations

import pytest

from app.core.sanitize import (
    MAX_SHORT_FIELD,
    clean_line,
    clean_text,
    hash_algorithm,
    normalize_domain,
    normalize_email,
    normalize_hash,
    normalize_ip,
    normalize_slug,
    strip_unsafe_characters,
)

pytestmark = pytest.mark.unit


class TestInvisibleAndControlCharacters:
    def test_bidi_override_is_removed(self) -> None:
        """`cmd.exe<RLO>tab.bat` renders as something else entirely in a console."""
        assert clean_line("cmd.exe‮tab.bat") == "cmd.exetab.bat"

    @pytest.mark.parametrize("char", ["​", "‎", "⁦", "﻿"])
    def test_zero_width_characters_are_removed(self, char: str) -> None:
        assert clean_line(f"power{char}shell.exe") == "powershell.exe"

    def test_null_byte_is_removed(self) -> None:
        assert clean_line("WIN-LAB-01\x00") == "WIN-LAB-01"

    def test_newlines_are_collapsed_in_single_line_fields(self) -> None:
        assert clean_line("host\nname") == "host name"

    def test_newlines_are_preserved_in_free_text(self) -> None:
        """A multi-line PowerShell command is evidence; flattening it loses meaning."""
        assert clean_text("line one\nline two") == "line one\nline two"

    def test_carriage_returns_are_normalised(self) -> None:
        assert clean_text("a\r\nb\rc") == "a\nb\nc"

    def test_unicode_is_nfc_normalised(self) -> None:
        composed = strip_unsafe_characters("é", allow_newlines=False)
        assert composed == "é"


class TestTruncation:
    def test_long_values_are_truncated_with_a_marker(self) -> None:
        result = clean_line("A" * 5_000, max_length=MAX_SHORT_FIELD)
        assert result is not None
        assert result.startswith("A" * 100)
        assert "truncated" in result

    def test_short_values_are_untouched(self) -> None:
        assert clean_line("powershell.exe") == "powershell.exe"

    def test_empty_becomes_none(self) -> None:
        assert clean_line("   ") is None
        assert clean_text("\x00\x00") is None
        assert clean_line(None) is None


class TestIpNormalisation:
    def test_ipv4_mapped_ipv6_collapses_to_ipv4(self) -> None:
        """Otherwise one host looks like two during correlation."""
        assert normalize_ip("::ffff:10.0.0.5") == "10.0.0.5"

    def test_ipv6_is_lower_cased_and_compressed(self) -> None:
        assert normalize_ip("2001:0DB8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"

    def test_brackets_are_stripped(self) -> None:
        assert normalize_ip("[2001:db8::1]") == "2001:db8::1"

    @pytest.mark.parametrize("bad", ["999.1.1.1", "10.0.0", "not-an-ip", "", "10.0.0.1/24"])
    def test_invalid_addresses_are_rejected(self, bad: str) -> None:
        with pytest.raises(ValueError, match=r"not a valid IP address|empty"):
            normalize_ip(bad)


class TestDomainNormalisation:
    def test_case_and_trailing_dot_are_normalised(self) -> None:
        assert normalize_domain("Evil.Example.COM.") == "evil.example.com"

    def test_internationalised_domain_becomes_punycode(self) -> None:
        """Compared in ASCII form so a lookalike cannot masquerade as an ASCII domain."""
        assert normalize_domain("bücher.example").startswith("xn--")

    @pytest.mark.parametrize("bad", ["not a domain", "example", "-bad.com", "a..b.com"])
    def test_invalid_domains_are_rejected(self, bad: str) -> None:
        with pytest.raises(ValueError):
            normalize_domain(bad)


class TestHashNormalisation:
    @pytest.mark.parametrize(
        "digest, algorithm",
        [("a" * 32, "md5"), ("B" * 40, "sha1"), ("c" * 64, "sha256")],
    )
    def test_valid_hashes_are_lower_cased_and_typed(self, digest: str, algorithm: str) -> None:
        normalised = normalize_hash(digest)
        assert normalised == digest.lower()
        assert hash_algorithm(normalised) == algorithm

    @pytest.mark.parametrize("bad", ["a" * 31, "z" * 64, "", "deadbeef"])
    def test_invalid_hashes_are_rejected(self, bad: str) -> None:
        with pytest.raises(ValueError):
            normalize_hash(bad)


class TestSlugAndEmail:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("Sysmon", "sysmon"),
            ("Windows Security", "windows_security"),
            ("Drift-Watch!", "drift-watch"),
        ],
    )
    def test_slugs(self, raw: str, expected: str) -> None:
        assert normalize_slug(raw) == expected

    def test_empty_slug_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            normalize_slug("!!!")

    def test_email_is_lower_cased(self) -> None:
        assert normalize_email("Analyst@Example.COM") == "analyst@example.com"

    @pytest.mark.parametrize("bad", ["no-at-sign", "a@b", "@example.com"])
    def test_invalid_emails_are_rejected(self, bad: str) -> None:
        with pytest.raises(ValueError):
            normalize_email(bad)
