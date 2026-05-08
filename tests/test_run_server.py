"""Tests for run_server dev/prod branching in web_server.py."""
import argparse
import importlib

import pytest


def _args(port=18000):
    """Return a minimal argparse.Namespace suitable for run_server."""
    return argparse.Namespace(port=port)


# ---------------------------------------------------------------------------
# Dev mode: CHECK_TLS_DEV=1  →  Flask built-in server
# ---------------------------------------------------------------------------

class TestRunServerDevMode:
    """When CHECK_TLS_DEV is set, run_server delegates to Flask app.run."""

    def test_calls_app_run_with_correct_args(self, monkeypatch):
        """app.run must receive host='::', port, and debug=True."""
        calls = {}

        def fake_run(self, host, port, debug):  # noqa: D401
            calls["host"] = host
            calls["port"] = port
            calls["debug"] = debug

        import flask
        monkeypatch.setenv("CHECK_TLS_DEV", "1")
        monkeypatch.setattr(flask.Flask, "run", fake_run)

        from check_tls.web_server import run_server
        run_server(_args(port=18001))

        assert calls["host"] == "::"
        assert calls["port"] == 18001
        assert calls["debug"] is True

    def test_accepts_true_value(self, monkeypatch):
        """CHECK_TLS_DEV=true (string) must also trigger dev mode."""
        calls = {}

        def fake_run(self, host, port, debug):
            calls["invoked"] = True

        import flask
        monkeypatch.setenv("CHECK_TLS_DEV", "true")
        monkeypatch.setattr(flask.Flask, "run", fake_run)

        from check_tls.web_server import run_server
        run_server(_args())

        assert calls.get("invoked") is True

    def test_does_not_call_waitress(self, monkeypatch):
        """When CHECK_TLS_DEV is set, waitress.serve must NOT be called."""
        import flask
        monkeypatch.setenv("CHECK_TLS_DEV", "1")
        monkeypatch.setattr(flask.Flask, "run", lambda *a, **kw: None)

        import waitress as _waitress
        waitress_calls = []
        monkeypatch.setattr(_waitress, "serve", lambda *a, **kw: waitress_calls.append((a, kw)))

        from check_tls.web_server import run_server
        run_server(_args())

        assert waitress_calls == []


# ---------------------------------------------------------------------------
# Production mode: no CHECK_TLS_DEV  →  waitress.serve
# ---------------------------------------------------------------------------

class TestRunServerProdMode:
    """Without CHECK_TLS_DEV, run_server must delegate to waitress.serve."""

    def test_calls_waitress_serve(self, monkeypatch):
        """waitress.serve must be called with the Flask app, listen, threads, ident."""
        monkeypatch.delenv("CHECK_TLS_DEV", raising=False)

        import waitress as _waitress
        calls = {}

        def fake_serve(app, listen, threads, ident):
            calls["app"] = app
            calls["listen"] = listen
            calls["threads"] = threads
            calls["ident"] = ident

        monkeypatch.setattr(_waitress, "serve", fake_serve)

        from check_tls.web_server import run_server
        run_server(_args(port=18002))

        assert calls["listen"] == "*:18002"
        assert calls["threads"] == 8
        assert calls["ident"] == "check-tls"

    def test_does_not_call_app_run(self, monkeypatch):
        """Flask's built-in server must NOT be called in production mode."""
        monkeypatch.delenv("CHECK_TLS_DEV", raising=False)

        import flask
        import waitress as _waitress
        flask_calls = []
        monkeypatch.setattr(flask.Flask, "run", lambda *a, **kw: flask_calls.append((a, kw)))
        monkeypatch.setattr(_waitress, "serve", lambda *a, **kw: None)

        from check_tls.web_server import run_server
        run_server(_args())

        assert flask_calls == []

    def test_app_passed_to_serve_is_flask_instance(self, monkeypatch):
        """The object passed to waitress.serve must be a Flask application."""
        import flask
        import waitress as _waitress
        monkeypatch.delenv("CHECK_TLS_DEV", raising=False)

        received = {}
        monkeypatch.setattr(_waitress, "serve", lambda app, listen, **kw: received.update(app=app))

        from check_tls.web_server import run_server
        run_server(_args())

        assert isinstance(received["app"], flask.Flask)
