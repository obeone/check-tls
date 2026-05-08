"""Tests for check_tls.utils.dns_utils.query_caa."""

import importlib

import dns.exception
import dns.resolver
import pytest

from check_tls.utils import dns_utils


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeRdata:
    """Minimal stand-in for a dnspython CAA rdata object."""

    def __init__(self, flags: int, tag: str, value: str) -> None:
        self.flags = flags
        self.tag = tag
        self.value = value


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestQueryCaaNoAnswer:
    """NoAnswer means the domain exists but has no CAA records."""

    def test_no_answer_returns_not_found(self, monkeypatch):
        """NoAnswer is treated as 'no records' — not an error."""
        monkeypatch.setattr(
            dns.resolver.Resolver,
            "resolve",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(dns.resolver.NoAnswer),
        )
        result = dns_utils.query_caa("example.com")
        assert result["checked"] is True
        assert result["found"] is False
        assert result["records"] == []
        assert result["error"] is None


class TestQueryCaaNXDOMAIN:
    """NXDOMAIN means the domain does not exist — also not an error for CAA."""

    def test_nxdomain_returns_not_found(self, monkeypatch):
        """NXDOMAIN is treated the same as NoAnswer."""
        monkeypatch.setattr(
            dns.resolver.Resolver,
            "resolve",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(dns.resolver.NXDOMAIN),
        )
        result = dns_utils.query_caa("nonexistent.invalid")
        assert result["checked"] is True
        assert result["found"] is False
        assert result["records"] == []
        assert result["error"] is None


class TestQueryCaaRecordParsing:
    """Records returned by the resolver are parsed into the expected shape."""

    def test_records_are_parsed(self, monkeypatch):
        """Resolver answers are converted to dicts with flags/tag/value keys."""
        fake_answers = [
            _FakeRdata(0, "issue", "letsencrypt.org"),
            _FakeRdata(128, "issuewild", ";"),
        ]
        monkeypatch.setattr(
            dns.resolver.Resolver,
            "resolve",
            lambda *_args, **_kwargs: fake_answers,
        )
        result = dns_utils.query_caa("example.com")
        assert result["checked"] is True
        assert result["found"] is True
        assert result["error"] is None
        assert len(result["records"]) == 2
        assert result["records"][0] == {"flags": 0, "tag": "issue", "value": "letsencrypt.org"}
        assert result["records"][1] == {"flags": 128, "tag": "issuewild", "value": ";"}


class TestQueryCaaTimeout:
    """Timeouts populate error without raising."""

    def test_lifetime_timeout_sets_error(self, monkeypatch):
        """dns.resolver.LifetimeTimeout is caught and surfaced in error field."""
        monkeypatch.setattr(
            dns.resolver.Resolver,
            "resolve",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(dns.resolver.LifetimeTimeout),
        )
        result = dns_utils.query_caa("slow.example.com")
        assert result["checked"] is True
        assert result["found"] is False
        assert result["records"] == []
        assert result["error"] is not None
        assert len(result["error"]) > 0

    def test_generic_timeout_sets_error(self, monkeypatch):
        """dns.exception.Timeout (base class) is also caught."""
        monkeypatch.setattr(
            dns.resolver.Resolver,
            "resolve",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(dns.exception.Timeout),
        )
        result = dns_utils.query_caa("slow.example.com")
        assert result["error"] is not None


class TestEnvVarOverride:
    """Module-level constants can be overridden via environment variables."""

    def test_dns_timeout_env_var(self, monkeypatch):
        """CHECK_TLS_DNS_TIMEOUT env var is picked up on module reload."""
        monkeypatch.setenv("CHECK_TLS_DNS_TIMEOUT", "0.7")
        importlib.reload(dns_utils)
        assert dns_utils.DNS_TIMEOUT_SEC == pytest.approx(0.7)
        # Restore defaults so other tests are not affected.
        monkeypatch.delenv("CHECK_TLS_DNS_TIMEOUT", raising=False)
        importlib.reload(dns_utils)

    def test_dns_lifetime_env_var(self, monkeypatch):
        """CHECK_TLS_DNS_LIFETIME env var is picked up on module reload."""
        monkeypatch.setenv("CHECK_TLS_DNS_LIFETIME", "3.5")
        importlib.reload(dns_utils)
        assert dns_utils.DNS_LIFETIME_SEC == pytest.approx(3.5)
        monkeypatch.delenv("CHECK_TLS_DNS_LIFETIME", raising=False)
        importlib.reload(dns_utils)

    def test_bad_env_var_falls_back_to_default(self, monkeypatch):
        """Non-numeric CHECK_TLS_DNS_TIMEOUT silently falls back to 2.0."""
        monkeypatch.setenv("CHECK_TLS_DNS_TIMEOUT", "not-a-number")
        importlib.reload(dns_utils)
        assert dns_utils.DNS_TIMEOUT_SEC == pytest.approx(2.0)
        monkeypatch.delenv("CHECK_TLS_DNS_TIMEOUT", raising=False)
        importlib.reload(dns_utils)

    def test_minimum_clamp(self, monkeypatch):
        """Values below 0.1 are clamped to 0.1 to prevent zero/negative timeouts."""
        monkeypatch.setenv("CHECK_TLS_DNS_TIMEOUT", "0.0")
        importlib.reload(dns_utils)
        assert dns_utils.DNS_TIMEOUT_SEC == pytest.approx(0.1)
        monkeypatch.delenv("CHECK_TLS_DNS_TIMEOUT", raising=False)
        importlib.reload(dns_utils)
