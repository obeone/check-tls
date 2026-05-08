"""Tests for :mod:`check_tls.utils.hsts_utils`."""

from typing import Optional

from check_tls.utils import hsts_utils
from check_tls.utils.hsts_utils import _parse_hsts_header, check_hsts


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeResponse:
    """Minimal stand-in for :class:`requests.Response` that exposes
    just the ``headers`` mapping consumed by :func:`check_hsts`."""

    def __init__(self, header_value: Optional[str] = None):
        self.headers = {}
        if header_value is not None:
            self.headers["Strict-Transport-Security"] = header_value


# ---------------------------------------------------------------------------
# Header parser
# ---------------------------------------------------------------------------

def test_parse_full_directive_set():
    parsed = _parse_hsts_header(
        "max-age=31536000; includeSubDomains; preload"
    )
    assert parsed == {
        "max_age": 31536000,
        "include_subdomains": True,
        "preload": True,
    }


def test_parse_quoted_max_age():
    parsed = _parse_hsts_header('max-age="63072000"; includeSubDomains')
    assert parsed["max_age"] == 63072000
    assert parsed["include_subdomains"] is True
    assert parsed["preload"] is False


def test_parse_directive_matching_is_case_insensitive():
    parsed = _parse_hsts_header(
        "MAX-AGE=10; INCLUDESUBDOMAINS; PRELOAD"
    )
    assert parsed == {
        "max_age": 10,
        "include_subdomains": True,
        "preload": True,
    }


def test_parse_zero_max_age():
    parsed = _parse_hsts_header("max-age=0")
    assert parsed["max_age"] == 0
    assert parsed["include_subdomains"] is False
    assert parsed["preload"] is False


def test_parse_malformed_max_age_yields_none():
    parsed = _parse_hsts_header("max-age=notanumber; preload")
    assert parsed["max_age"] is None
    assert parsed["preload"] is True


def test_parse_empty_string():
    assert _parse_hsts_header("") == {
        "max_age": None,
        "include_subdomains": False,
        "preload": False,
    }


# ---------------------------------------------------------------------------
# check_hsts
# ---------------------------------------------------------------------------

def test_check_hsts_full_policy(monkeypatch):
    captured = {}

    def fake_fetch(url, *, method="GET", **kwargs):
        captured["url"] = url
        captured["method"] = method
        return _FakeResponse(
            "max-age=31536000; includeSubDomains; preload"
        )

    monkeypatch.setattr(hsts_utils, "safe_http_fetch", fake_fetch)
    result = check_hsts("example.com")

    assert captured["url"] == "https://example.com/"
    assert captured["method"] == "HEAD"
    assert result["checked"] is True
    assert result["header_present"] is True
    assert result["max_age"] == 31536000
    assert result["include_subdomains"] is True
    assert result["preload"] is True
    assert result["error"] is None


def test_check_hsts_custom_port_in_url(monkeypatch):
    captured = {}

    def fake_fetch(url, *, method="GET", **kwargs):
        captured["url"] = url
        return _FakeResponse("max-age=600")

    monkeypatch.setattr(hsts_utils, "safe_http_fetch", fake_fetch)
    check_hsts("example.com", port=8443)
    assert captured["url"] == "https://example.com:8443/"


def test_check_hsts_no_header(monkeypatch):
    monkeypatch.setattr(
        hsts_utils, "safe_http_fetch", lambda *a, **k: _FakeResponse(None)
    )
    result = check_hsts("example.com")
    assert result["header_present"] is False
    assert result["max_age"] is None
    assert result["include_subdomains"] is False
    assert result["preload"] is False
    assert result["error"] is None
    assert result["raw_header"] is None


def test_check_hsts_fetch_failure_returns_error(monkeypatch):
    monkeypatch.setattr(
        hsts_utils, "safe_http_fetch", lambda *a, **k: None
    )
    result = check_hsts("blocked.example")
    assert result["checked"] is True
    assert result["header_present"] is False
    assert result["error"] is not None
    assert "HSTS check failed" in result["error"]


def test_check_hsts_zero_max_age(monkeypatch):
    monkeypatch.setattr(
        hsts_utils,
        "safe_http_fetch",
        lambda *a, **k: _FakeResponse("max-age=0"),
    )
    result = check_hsts("example.com")
    assert result["header_present"] is True
    assert result["max_age"] == 0
    assert result["raw_header"] == "max-age=0"


def test_check_hsts_malformed_header(monkeypatch):
    monkeypatch.setattr(
        hsts_utils,
        "safe_http_fetch",
        lambda *a, **k: _FakeResponse("garbage; max-age=oops"),
    )
    result = check_hsts("example.com")
    assert result["header_present"] is True
    assert result["max_age"] is None
    assert result["include_subdomains"] is False
    assert result["preload"] is False
