# tests/test_domain_parser.py
"""Unit tests for check_tls.utils.domain_parser.parse_domain_entry."""

import pytest

from check_tls.utils.domain_parser import DEFAULT_PORT, ParsedDomain, parse_domain_entry


class TestPlainHostname:
    """parse_domain_entry with a bare hostname."""

    def test_plain_host_uses_default_port(self):
        """Plain hostname with no port resolves to DEFAULT_PORT."""
        result = parse_domain_entry("example.com")
        assert result.host == "example.com"
        assert result.port == DEFAULT_PORT

    def test_plain_host_custom_default_port(self):
        """Custom default_port is used when no port is present in entry."""
        result = parse_domain_entry("example.com", default_port=8000)
        assert result.port == 8000

    def test_original_preserved(self):
        """The original input string is stored verbatim."""
        entry = "example.com"
        result = parse_domain_entry(entry)
        assert result.original == entry


class TestHostWithPort:
    """parse_domain_entry with host:port notation."""

    def test_host_colon_port(self):
        """host:port is parsed correctly."""
        result = parse_domain_entry("example.com:8443")
        assert result.host == "example.com"
        assert result.port == 8443

    def test_original_preserved_with_port(self):
        """original field is verbatim even when a port is embedded."""
        entry = "example.com:8443"
        result = parse_domain_entry(entry)
        assert result.original == entry


class TestUrlForms:
    """parse_domain_entry with full URLs."""

    def test_https_url_no_port(self):
        """https://host without explicit port resolves to DEFAULT_PORT."""
        result = parse_domain_entry("https://example.com")
        assert result.host == "example.com"
        assert result.port == DEFAULT_PORT

    def test_https_url_with_port_and_path(self):
        """https://host:port/path extracts port from URL."""
        result = parse_domain_entry("https://example.com:9443/path")
        assert result.host == "example.com"
        assert result.port == 9443

    def test_http_url(self):
        """http:// scheme is accepted and parsed."""
        result = parse_domain_entry("http://example.com:8080")
        assert result.host == "example.com"
        assert result.port == 8080

    def test_original_preserved_for_url(self):
        """original field is the verbatim URL."""
        entry = "https://example.com:9443/path"
        result = parse_domain_entry(entry)
        assert result.original == entry


class TestIPv6:
    """parse_domain_entry with IPv6 literals."""

    def test_bracketed_ipv6_with_port(self):
        """[::1]:443 is handled by urlparse; host has no brackets."""
        result = parse_domain_entry("[::1]:443")
        assert result.host == "::1"
        assert result.port == 443

    def test_bracketed_ipv6_no_port(self):
        """https://[::1] resolves to DEFAULT_PORT."""
        result = parse_domain_entry("https://[::1]")
        assert result.host == "::1"
        assert result.port == DEFAULT_PORT


class TestInvalidPorts:
    """parse_domain_entry falls back to default on bad port values."""

    def test_non_numeric_port_falls_back(self):
        """Non-numeric port token falls back to default_port."""
        result = parse_domain_entry("example.com:foo")
        assert result.port == DEFAULT_PORT

    def test_out_of_range_port_falls_back(self):
        """Port > 65535 falls back to default_port."""
        result = parse_domain_entry("example.com:99999")
        assert result.port == DEFAULT_PORT

    def test_zero_port_falls_back(self):
        """Port 0 (out of range) falls back to default_port."""
        result = parse_domain_entry("example.com:0")
        assert result.port == DEFAULT_PORT

    def test_invalid_port_custom_default(self):
        """Custom default_port is used when port is invalid."""
        result = parse_domain_entry("example.com:foo", default_port=9000)
        assert result.port == 9000


class TestReturnType:
    """parse_domain_entry always returns a ParsedDomain dataclass."""

    def test_returns_parsed_domain_instance(self):
        """Return value is a ParsedDomain."""
        result = parse_domain_entry("example.com")
        assert isinstance(result, ParsedDomain)

    def test_frozen_dataclass(self):
        """ParsedDomain is immutable (frozen=True)."""
        result = parse_domain_entry("example.com")
        with pytest.raises(Exception):
            result.host = "other.com"  # type: ignore[misc]
