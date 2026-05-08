"""
End-to-end STARTTLS and ALPN tests.

Spins up tiny in-process servers that speak the plaintext SMTP/IMAP/POP3
banner+upgrade dance, then hand the socket to ``ssl.SSLContext.wrap_socket``
in server mode. Verifies that ``analyze_certificates(... starttls="smtp")``
(and friends) successfully retrieve the leaf certificate. ALPN tests use
the same server scaffolding and assert the negotiated value surfaces in
``connection_health.alpn_protocol``.
"""

from __future__ import annotations

import socket
import ssl
import threading

import pytest

from check_tls.tls_checker import (
    analyze_certificates,
    fetch_leaf_certificate_and_conn_info,
)
from test_tls_checker import generate_self_signed_cert


def _start_starttls_server(cert_path, key_path, protocol, alpn_select=None):
    """
    Run a single-shot plaintext-then-TLS server for SMTP/IMAP/POP3.

    Parameters
    ----------
    cert_path : str
        Path to a PEM certificate the TLS server will present.
    key_path : str
        Path to the matching PEM private key.
    protocol : str
        ``"smtp"``, ``"imap"`` or ``"pop3"``. Drives the banner exchange.
    alpn_select : str or None
        If set, the server advertises ALPN and forces the given protocol
        as the negotiated value (mirrors what real servers do).

    Returns
    -------
    (int, callable)
        The bound port and a ``stop()`` callable that joins the thread.
    """
    listen_sock = socket.socket()
    listen_sock.bind(("127.0.0.1", 0))
    listen_sock.listen(1)
    port = listen_sock.getsockname()[1]
    stop_event = threading.Event()

    def run():
        try:
            listen_sock.settimeout(5)
            client, _ = listen_sock.accept()
        except OSError:
            return
        try:
            client.settimeout(5)

            if protocol == "smtp":
                client.sendall(b"220 test.example ESMTP ready\r\n")
                # Read EHLO line.
                _read_line(client)
                client.sendall(b"250-test.example\r\n250 STARTTLS\r\n")
                # Read STARTTLS line.
                _read_line(client)
                client.sendall(b"220 Ready to start TLS\r\n")
            elif protocol == "imap":
                client.sendall(b"* OK IMAP test ready\r\n")
                _read_line(client)  # a001 STARTTLS
                client.sendall(b"a001 OK Begin TLS negotiation now\r\n")
            elif protocol == "pop3":
                client.sendall(b"+OK POP3 test ready\r\n")
                _read_line(client)  # STLS
                client.sendall(b"+OK Begin TLS\r\n")
            else:
                raise RuntimeError(f"Unknown protocol {protocol}")

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            if alpn_select:
                ctx.set_alpn_protocols([alpn_select])

            try:
                with ctx.wrap_socket(client, server_side=True) as ssock:
                    # Drain a byte to keep the client side blocking long
                    # enough to retrieve the cert; we don't care otherwise.
                    try:
                        ssock.recv(1)
                    except Exception:
                        pass
            except Exception:
                pass
        finally:
            try:
                client.close()
            except Exception:
                pass
            try:
                listen_sock.close()
            except Exception:
                pass

    def _read_line(s):
        buf = b""
        while not buf.endswith(b"\n") and len(buf) < 4096:
            chunk = s.recv(1)
            if not chunk:
                break
            buf += chunk
        return buf

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    def stop():
        stop_event.set()
        try:
            listen_sock.close()
        except Exception:
            pass
        thread.join(timeout=5)

    return port, stop


def _start_alpn_tls_server(cert_path, key_path, alpn_select=None):
    """
    Plain TLS server that optionally advertises ALPN.

    Returns ``(port, stop)`` like the helper above. When ``alpn_select`` is
    None, no ALPN is configured server-side, simulating servers that do
    not negotiate ALPN at all.
    """
    listen_sock = socket.socket()
    listen_sock.bind(("127.0.0.1", 0))
    listen_sock.listen(1)
    port = listen_sock.getsockname()[1]

    def run():
        try:
            listen_sock.settimeout(5)
            client, _ = listen_sock.accept()
        except OSError:
            return
        try:
            client.settimeout(5)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            if alpn_select:
                ctx.set_alpn_protocols([alpn_select])
            try:
                with ctx.wrap_socket(client, server_side=True) as ssock:
                    try:
                        ssock.recv(1)
                    except Exception:
                        pass
            except Exception:
                pass
        finally:
            try:
                client.close()
            except Exception:
                pass
            try:
                listen_sock.close()
            except Exception:
                pass

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    def stop():
        try:
            listen_sock.close()
        except Exception:
            pass
        thread.join(timeout=5)

    return port, stop


def _redirect_to_localhost(monkeypatch):
    """
    Redirect outbound connections to 127.0.0.1 while preserving the port.

    Lets us point the analyzer at a domain like ``starttls.test`` (which
    fails the SAN/CN match unless the cert's SAN includes it) and still
    have the TCP connection land on the test server bound to localhost.
    """
    real_create_connection = socket.create_connection

    def redirected(address, *args, **kwargs):
        host, p = address
        return real_create_connection(("127.0.0.1", p), *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", redirected)


def test_alpn_negotiated_protocol_reported(monkeypatch):
    """ALPN h2 negotiated server-side surfaces in conn_info.alpn_protocol."""
    cert, cert_path, key_path = generate_self_signed_cert(
        "alpn.test", ["alpn.test"],
    )
    port, stop = _start_alpn_tls_server(cert_path, key_path, alpn_select="h2")
    _redirect_to_localhost(monkeypatch)
    try:
        leaf, conn_info = fetch_leaf_certificate_and_conn_info(
            "alpn.test", port=port, insecure=True
        )
        assert leaf is not None
        assert conn_info["alpn_protocol"] == "h2"
    finally:
        stop()


def test_alpn_absent_when_server_does_not_negotiate(monkeypatch):
    """When the server doesn't advertise ALPN, alpn_protocol stays None."""
    cert, cert_path, key_path = generate_self_signed_cert(
        "noalpn.test", ["noalpn.test"],
    )
    port, stop = _start_alpn_tls_server(cert_path, key_path, alpn_select=None)
    _redirect_to_localhost(monkeypatch)
    try:
        leaf, conn_info = fetch_leaf_certificate_and_conn_info(
            "noalpn.test", port=port, insecure=True
        )
        assert leaf is not None
        assert conn_info["alpn_protocol"] is None
    finally:
        stop()


@pytest.mark.parametrize("protocol", ["smtp", "imap", "pop3"])
def test_starttls_handshake_retrieves_certificate(monkeypatch, protocol):
    """STARTTLS upgrade succeeds for SMTP/IMAP/POP3 and returns the cert."""
    cert, cert_path, key_path = generate_self_signed_cert(
        "starttls.test", ["starttls.test"],
    )
    port, stop = _start_starttls_server(cert_path, key_path, protocol)
    _redirect_to_localhost(monkeypatch)
    try:
        result = analyze_certificates(
            "starttls.test",
            port=port,
            mode="simple",
            insecure=True,
            skip_transparency=True,
            perform_crl_check=False,
            perform_ocsp_check=False,
            perform_caa_check=False,
            starttls=protocol,
        )
        assert result["status"] != "failed", result.get("error_message")
        assert result["connection_health"]["checked"] is True
        assert result["certificates"], "no certificate parsed"
        leaf = result["certificates"][0]
        assert leaf["common_name"] == "starttls.test"
    finally:
        stop()


def test_starttls_ldap_returns_clean_error():
    """Requesting starttls='ldap' surfaces an explicit ValueError."""
    from check_tls.tls_checker import _starttls_upgrade

    s = socket.socket()
    try:
        with pytest.raises(ValueError) as exc_info:
            _starttls_upgrade(s, "ldap")
        assert "LDAP" in str(exc_info.value).upper()
    finally:
        s.close()


def test_starttls_unknown_protocol_returns_clean_error():
    """Unknown STARTTLS protocols raise ValueError, not a generic OSError."""
    from check_tls.tls_checker import _starttls_upgrade

    s = socket.socket()
    try:
        with pytest.raises(ValueError) as exc_info:
            _starttls_upgrade(s, "ftp")
        assert "ftp" in str(exc_info.value)
    finally:
        s.close()
