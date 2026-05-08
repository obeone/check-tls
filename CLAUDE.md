# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common commands

Project uses `uv` for environments and `pytest`/`ruff` for tests/lint (see project memory).

```sh
# Editable install for development
uv pip install -e .

# Run from source (no install required if PYTHONPATH=src)
python -m check_tls.main example.com
python -m check_tls.main --server -p 8000   # web UI on http://*:8000 (IPv4 + IPv6 via Waitress)
CHECK_TLS_DEV=1 python -m check_tls.main --server -p 8000  # dev mode: Werkzeug with live reload (NOT for prod)

# Tests
pytest                                       # full suite
pytest tests/test_tls_checker.py -k mismatch # single test by name pattern

# Lint
ruff check .

# Build wheel/sdist (versioned via setuptools_scm from git tags)
python -m build
SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0 python -m build   # when not on a tagged commit

# Docker (multi-stage, Alpine + Rust for cryptography)
docker build --build-arg APP_VERSION=0.0.0 -t check-tls .
docker run --rm check-tls example.com
docker run --rm -p 8000:8000 check-tls --server
```

The console script `check-tls` (defined in `pyproject.toml`) is identical to `python -m check_tls.main`.

## Architecture

Single Python package `check_tls` exposing both a CLI and a Flask web UI/REST API over the same analysis core. `src/` layout; `setuptools_scm` derives `__version__` from git tags at install time (falls back to `0.0.0` when the package metadata is missing).

Three layers:

1. **Entry points** — `check_tls.main` (CLI / argparse + shtab completion) and `check_tls.web_server` (Flask app factory `get_flask_app()` + `run_server()`). Both parse a domain spec into `(host, port)` using the same logic: schemes are added when missing, then `urllib.parse.urlparse` extracts host/port, with a manual `host:port` fallback. Any change to that parsing must be applied in **both** places (`main.py` and `web_server.py::api_analyze`) to keep CLI and API behavior in sync.

2. **Analysis core** — `check_tls.tls_checker`. The two public entry points are:
   - `analyze_certificates(domain, port, mode, insecure, skip_transparency, perform_crl_check, perform_ocsp_check, perform_caa_check)` → returns the per-domain result dict (keys: `domain`, `status`, `connection_health`, `validation`, `certificates`, `crl_check`, `transparency`, `ocsp_check`, `caa_check`, optional `error_message`). This is the canonical result shape used by JSON output, CSV output, the HTML template, and the REST API. Any new field must be added consistently across all four consumers.
   - `run_analysis(...)` — multi-domain wrapper that handles JSON/CSV file output (`-` means stdout).
   - `fetch_leaf_certificate_and_conn_info()` deliberately disables `check_hostname` on the SSL context so the leaf certificate is always retrievable; hostname verification is then performed manually using `ssl._dnsname_match` so mismatches surface in `connection_health.error` with full `not_valid_before` / `not_valid_after` context (the regression tests in `tests/test_tls_checker.py` assert this exact behavior — don't switch back to automatic hostname checking).

3. **Utilities** — `check_tls.utils` provides single-purpose modules: `cert_utils` (x509 parsing, SAN/CN extraction, profile detection from KeyUsage/EKU), `crl_utils` (CRL fetch + revocation check), `crtsh_utils` (Certificate Transparency via crt.sh), `dns_utils` (CAA records via `dnspython`), `ocsp_utils` (OCSP responder check). `tls_checker.py` does `from check_tls.utils.cert_utils import *` — when adding helpers there, mind the wildcard surface.

Web UI assets live in `src/check_tls/templates/` and `src/check_tls/static/` and are packaged via `[tool.setuptools.package-data]`. The Flask app resolves them via paths relative to `web_server.py`, not via `package_data` lookups, so renaming those folders requires updating `get_flask_app()`.

The web server binds to `*` (Waitress wildcard — dual-stack IPv4+IPv6 on all interfaces) — keep it that way; it's a documented feature.  Setting `CHECK_TLS_DEV=1` falls back to Flask's Werkzeug dev server with `debug=True`; never use that in production.

## Testing notes

Tests in `tests/test_tls_checker.py` spin up an in-process TLS server on `127.0.0.1` with a self-signed or CA-signed cert (built via `cryptography`) to exercise hostname-mismatch and expired-cert error reporting end-to-end. The expired-cert test monkeypatches `ssl.create_default_context` to inject a custom CA — preserve that pattern instead of mocking `analyze_certificates` internals. Tests assert exact substrings in error messages (`"Hostname mismatch"`, `"SSL certificate verification failed"`, `not_valid_before_utc.isoformat()`); error-message wording is part of the contract.

## Release flow

Two GitHub Actions workflows in `.github/workflows/`:

- `publish-to-pypi.yaml` — runs on GitHub release publish; builds with `python -m build` and `twine upload`s. The release tag must match the version `setuptools_scm` will derive.
- `build-and-publish.yaml` — Docker multi-arch build (`linux/amd64,arm64,i386`), pushes to `ghcr.io/obeone/check-tls` and `docker.io/obeoneorg/check-tls`, signs with cosign. Tag-named images are produced only on `release` events; `main` pushes update `:latest` only.

`APP_VERSION` is plumbed into the Dockerfile via `--build-arg` so the wheel built inside the image carries the right version (`SETUPTOOLS_SCM_PRETEND_VERSION`).
