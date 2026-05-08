"""
test_security_utils.py

Regression coverage for the SSRF protections in
:mod:`check_tls.utils.security_utils`. The tests focus on
:func:`safe_http_fetch` because it is the only entry point the AIA,
CRL and OCSP fetchers go through after the SSRF-redirect-bypass fix.

The pytest suite is launched with ``ALLOW_INTERNAL_IPS=true`` so
loopback test fixtures can serve traffic. Tests that need to *prove*
a private-IP target is rejected scope the environment variable back
to ``"false"`` for the duration of the test via
:func:`pytest.MonkeyPatch.setenv`. For the redirect-target test we
instead monkeypatch :func:`validate_host_for_connection` so the first
hop to the test server is allowed but loopback redirect targets are
still refused — that precisely models the threat: the
AIA/CRL/OCSP server is "trusted" but its 302 points at
``169.254.169.254`` / ``127.0.0.1``.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, List, Tuple

import pytest

from check_tls.utils import security_utils
from check_tls.utils.security_utils import safe_http_fetch


def _start_http_server(
    handler_factory: Callable[[List[Tuple[str, str]]], type],
) -> Tuple[HTTPServer, List[Tuple[str, str]], Callable[[], None]]:
    """
    Start an in-process HTTP server bound to ``127.0.0.1`` on an ephemeral port.

    Parameters
    ----------
    handler_factory : Callable
        Factory taking the shared request log list and returning a
        :class:`http.server.BaseHTTPRequestHandler` subclass.

    Returns
    -------
    tuple
        ``(server, request_log, stop)`` where ``server`` is the live
        :class:`HTTPServer`, ``request_log`` is a list mutated by the
        handler (one ``(method, path)`` tuple per served request), and
        ``stop`` is a callable that shuts the server down and joins
        the serving thread.
    """
    request_log: List[Tuple[str, str]] = []
    handler_cls = handler_factory(request_log)
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def stop() -> None:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    return server, request_log, stop


def _ok_handler_factory(request_log: List[Tuple[str, str]]) -> type:
    """Build a handler that replies ``200 OK`` with a fixed body."""

    class _OkHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:  # noqa: A002
            return

        def _serve(self) -> None:
            request_log.append((self.command, self.path))
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            self._serve()

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length:
                self.rfile.read(length)
            self._serve()

    return _OkHandler


def _redirect_handler_factory(target_url: str) -> Callable[[List[Tuple[str, str]]], type]:
    """Return a factory that builds a 302-redirect handler pointing at ``target_url``."""

    def factory(request_log: List[Tuple[str, str]]) -> type:
        class _RedirectHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args) -> None:  # noqa: A002
                return

            def do_GET(self) -> None:  # noqa: N802
                request_log.append((self.command, self.path))
                self.send_response(302)
                self.send_header("Location", target_url)
                self.send_header("Content-Length", "0")
                self.end_headers()

        return _RedirectHandler

    return factory


def _chain_factory(
    state: dict,
) -> Callable[[List[Tuple[str, str]]], type]:
    """
    Build a handler that walks ``state['chain']`` of redirect Locations.

    The handler reads the chain list from a shared mutable ``state``
    dict so the caller can rewrite the absolute URLs once the server
    port is known.
    """

    def factory(request_log: List[Tuple[str, str]]) -> type:
        class _ChainHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args) -> None:  # noqa: A002
                return

            def do_GET(self) -> None:  # noqa: N802
                request_log.append((self.command, self.path))
                idx = state["index"]
                chain = state["chain"]
                if idx < len(chain):
                    state["index"] = idx + 1
                    self.send_response(302)
                    self.send_header("Location", chain[idx])
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = b"final"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        return _ChainHandler

    return factory


def test_safe_http_fetch_rejects_direct_private_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    """Initial URL pointing at 127.0.0.1 must be blocked when SSRF guard is active."""
    # Force the guard back on for this test even though the suite runs
    # with ALLOW_INTERNAL_IPS=true.
    monkeypatch.setenv("ALLOW_INTERNAL_IPS", "false")

    # Bind a server but never expect it to be hit; safe_http_fetch must
    # short-circuit before any socket connection to the loopback target.
    server, request_log, stop = _start_http_server(_ok_handler_factory)
    port = server.server_address[1]
    try:
        result = safe_http_fetch(f"http://127.0.0.1:{port}/")
        assert result is None
        assert request_log == [], "server should never have been contacted"
    finally:
        stop()


def test_safe_http_fetch_rejects_redirect_to_private_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    A 302 from an allowed first hop pointing at a private IP must be refused.

    The historic SSRF bypass was exactly this: the initial URL passes
    the allowlist but the redirect target is a metadata / loopback
    address. We monkeypatch :func:`validate_host_for_connection` so
    the first hop is allowed and the loopback redirect target is
    rejected — proving ``safe_http_fetch`` re-validates each hop.
    """
    # Redirect to a clearly internal address that is never bound.
    blocked_target = "http://169.254.169.254/latest/meta-data/"
    server, request_log, stop = _start_http_server(
        _redirect_handler_factory(blocked_target)
    )
    port = server.server_address[1]

    real_validate = security_utils.validate_host_for_connection

    def selective_validate(host, p, allow_private_ips=False):
        # Allow only the test server's host:port; everything else goes
        # through the real (strict) validator regardless of the env.
        if host == "127.0.0.1" and p == port:
            return True, None
        return real_validate(host, p, allow_private_ips=False)

    monkeypatch.setattr(
        security_utils,
        "validate_host_for_connection",
        selective_validate,
    )

    try:
        result = safe_http_fetch(f"http://127.0.0.1:{port}/")
        assert result is None
        # Initial hop was made; the redirect was inspected and rejected
        # before being followed, so only one request hits the wire.
        assert request_log == [("GET", "/")]
    finally:
        stop()


def test_safe_http_fetch_follows_allowed_redirect_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multi-hop redirect chain entirely on the allowlist should succeed."""
    # Suite-level ALLOW_INTERNAL_IPS=true is enough; pin it for clarity.
    monkeypatch.setenv("ALLOW_INTERNAL_IPS", "true")

    state = {"index": 0, "chain": []}
    server, request_log, stop = _start_http_server(_chain_factory(state))
    port = server.server_address[1]
    state["chain"] = [
        f"http://127.0.0.1:{port}/step2",
        f"http://127.0.0.1:{port}/step3",
    ]
    try:
        result = safe_http_fetch(f"http://127.0.0.1:{port}/start")
        assert result is not None
        assert result.status_code == 200
        assert result.content == b"final"
        # Three hops total: /start -> /step2 -> /step3.
        paths = [path for _method, path in request_log]
        assert paths == ["/start", "/step2", "/step3"]
    finally:
        stop()


def test_safe_http_fetch_max_redirects_exceeded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A redirect loop deeper than ``max_redirects`` must yield ``None``."""
    monkeypatch.setenv("ALLOW_INTERNAL_IPS", "true")

    def factory(request_log: List[Tuple[str, str]]) -> type:
        class _LoopHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args) -> None:  # noqa: A002
                return

            def do_GET(self) -> None:  # noqa: N802
                request_log.append((self.command, self.path))
                self.send_response(302)
                self.send_header("Location", "/loop")
                self.send_header("Content-Length", "0")
                self.end_headers()

        return _LoopHandler

    server, request_log, stop = _start_http_server(factory)
    port = server.server_address[1]
    try:
        result = safe_http_fetch(
            f"http://127.0.0.1:{port}/loop",
            max_redirects=2,
        )
        assert result is None
        # Initial request + 2 redirect follow-ups = 3 entries on the wire.
        assert len(request_log) == 3
    finally:
        stop()


def test_safe_http_fetch_rejects_non_http_scheme(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non HTTP(S) schemes must be rejected before any I/O happens."""
    monkeypatch.setenv("ALLOW_INTERNAL_IPS", "true")

    assert safe_http_fetch("file:///etc/passwd") is None
    assert safe_http_fetch("ftp://example.com/foo") is None
    assert safe_http_fetch("gopher://example.com/0/x") is None


def test_is_ip_blocked_invalid_input_fails_closed() -> None:
    """
    A non-IP literal must be reported as blocked, not silently allowed.

    The historical implementation returned ``(False, None)`` for any
    string that did not parse as an IP, which was a fail-open hole if a
    malformed value reached :func:`is_ip_blocked` directly. The new
    behavior is fail-closed.
    """
    is_blocked, msg = security_utils.is_ip_blocked("not-an-ip")
    assert is_blocked is True
    assert msg is not None
    assert "Invalid IP address" in msg
    assert "not-an-ip" in msg

    # Empty string is equally malformed and must also be blocked.
    is_blocked, msg = security_utils.is_ip_blocked("")
    assert is_blocked is True
    assert msg is not None
    assert "Invalid IP address" in msg


def test_is_ip_blocked_valid_public_ip_still_allowed() -> None:
    """A public IP literal must still pass ``is_ip_blocked`` cleanly."""
    is_blocked, msg = security_utils.is_ip_blocked("8.8.8.8")
    assert is_blocked is False
    assert msg is None


def test_is_ip_blocked_private_ip_blocked_with_message() -> None:
    """A private IP literal must be blocked with a descriptive message."""
    is_blocked, msg = security_utils.is_ip_blocked("192.168.1.1")
    assert is_blocked is True
    assert msg is not None
    assert "192.168.1.1" in msg
    assert "192.168.0.0/16" in msg


def test_validate_host_blocks_invalid_resolved_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    A malformed IP returned by ``getaddrinfo`` must propagate as a
    blocked verdict from ``validate_host_for_connection`` thanks to
    ``is_ip_blocked``'s fail-closed posture.
    """
    monkeypatch.setenv("ALLOW_INTERNAL_IPS", "false")

    def fake_getaddrinfo(host, port, family, socktype):
        return [(security_utils.socket.AF_INET, socktype, 0, "", ("not-an-ip", port))]

    monkeypatch.setattr(security_utils.socket, "getaddrinfo", fake_getaddrinfo)

    is_valid, err = security_utils.validate_host_for_connection(
        "weird.example", 443
    )
    assert is_valid is False
    assert err is not None
    assert "Invalid IP address" in err
