# ✨ Check TLS Certificate ✨

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI Version](https://img.shields.io/pypi/v/check-tls.svg)](https://pypi.org/project/check-tls/)
[![Docker Hub](https://img.shields.io/badge/Docker%20Hub-obeoneorg%2Fcheck--tls-blue?logo=docker)](https://hub.docker.com/r/obeoneorg/check-tls)
[![GHCR.io](https://img.shields.io/badge/GHCR.io-obeone%2Fcheck--tls-blue?logo=github)](https://ghcr.io/obeone/check-tls)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/obeone/check-tls)

A powerful, developer-friendly Python tool to analyze TLS/SSL certificates for any domain.

---

## 📚 Table of Contents

- [✨ Check TLS Certificate ✨](#-check-tls-certificate-)
  - [📚 Table of Contents](#-table-of-contents)
  - [🚀 Features](#-features)
  - [🛠️ Installation](#️-installation)
    - [Recommended: With pipx](#recommended-with-pipx)
    - [Alternative: With pip](#alternative-with-pip)
    - [With Docker](#with-docker)
  - [⚙️ Usage](#️-usage)
    - [Example (pip)](#example-pip)
    - [Command Line](#command-line)
  - [🖥️ REST API Usage](#️-rest-api-usage)
    - [Analyze Domains (POST /api/analyze)](#analyze-domains-post-apianalyze)
      - [Example curl Request](#example-curl-request)
      - [Example JSON Response](#example-json-response)
    - [OCSP Status](#ocsp-status)
  - [🌐 Web Interface](#-web-interface)
  - [✨ Shell Completion](#-shell-completion)
  - [❓ FAQ](#-faq)
  - [🛠️ Troubleshooting](#️-troubleshooting)
  - [👩‍💻 Development](#-development)
  - [🤝 Contributing](#-contributing)
  - [📜 License](#-license)
  - [📦 Release \& Publish](#-release--publish)

---

## 🚀 Features

- **Comprehensive Analysis**: Fetches leaf & intermediate certificates (AIA fetching)
- **Chain Validation**: Validates against system trust store
- **Profile Detection**: Detects usage profiles (server, email, code signing, etc.)
- **CRL & Transparency**: Checks CRL status and certificate transparency logs
- **OCSP Check**: Perform OCSP revocation checks for leaf certificates.
- **Flexible Output**: Human-readable (color), JSON, CSV
- **Web UI**: Interactive browser-based analysis
- **Dockerized**: Use with zero local setup

---

## 🛠️ Installation

### Recommended: With pipx

`pipx` installs CLI tools in isolated environments, avoiding dependency conflicts and keeping your system clean.

```sh
pipx install check-tls
```

### Alternative: With pip

```sh
pip install check-tls
```

### With Docker

```sh
docker pull obeoneorg/check-tls:latest
```

---

## ⚙️ Usage

### Example (pip)

Analyze a domain:

```sh
check-tls example.com
```

Run the web UI:

```sh
check-tls --server
```

Visit <http://localhost:8000> in your browser.

### Command Line

![Screenshot of CLI Output](screenshot_cli.png)
*Example: Command-line output for analyzing a domain (including OCSP status)*

Analyze a domain:

```sh
check-tls example.com
# Or with a full URL (port in URL overrides --connect-port)
check-tls https://example.net:9000
```

Analyze multiple domains, output JSON:

```sh
check-tls google.com https://github.com:443 -j report.json
```

Human-readable output (default), or use `-j` for JSON and `-c` for CSV.

**Key options:**

- `-j, --json FILE`   Output JSON (use "-" for stdout)                                  
- `-c, --csv FILE`    Output CSV (use "-" for stdout)
- `-P CONNECT_PORT, --connect-port CONNECT_PORT`
                        Port to connect to for TLS analysis (default: 443).
                        This is overridden if port is specified in domain/URL string
                        e.g. example.com:1234 or https://example.com:1234
- `-k, --insecure`    Allow self-signed certs
- `-s, --server`      Launch web UI
- `-p, --port`        Web server port (for the UI, not for TLS connection)
- `--no-transparency` Skip transparency check
- `--no-crl-check`    Skip CRL check
- `--no-ocsp-check`   Disable OCSP revocation check (enabled by default)

---

## 🖥️ REST API Usage

The TLS Analyzer also provides a REST API for programmatic access. By default, the web server listens on port 8000.

### Analyze Domains (POST /api/analyze)

- **Endpoint:** `/api/analyze`
- **Method:** `POST`
- **Content-Type:** `application/json`
- **Request Body:**
  - `domains` (array of strings, required): List of domains to analyze (e.g. `["example.com", "google.com"]`)
  - `insecure` (optional, boolean): Allow insecure (self-signed) certs
  - `no_transparency` (optional, boolean): Skip certificate transparency check
  - `no_crl_check` (optional, boolean): Disable CRL check
  - `no_ocsp_check` (optional, boolean): Disable OCSP check

#### Example curl Request

```sh
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com", "google.com"], "insecure": true, "no_transparency": true}'
```

#### Example JSON Response

```json
[
  {
    "domain": "example.com",
    "status": "completed",
    "analysis_timestamp": "2025-04-26T08:30:00+00:00",
    "connection_health": { ... },
    "validation": { ... },
    "certificates": [ ... ],
    "crl_check": { ... },
    "transparency": { ... }
  },
  ...
]
```

---

### OCSP Status

The tool provides the following OCSP statuses for the leaf certificate:

- **`good`**: The certificate is valid according to its OCSP responder.
- **`revoked`**: The certificate has been revoked according to its OCSP responder.
- **`unknown`**: The OCSP responder replied with an "unknown" status for the certificate. This means the responder doesn't have information about the certificate's status.
- **`error`**: An error occurred while trying to perform the OCSP check (e.g., network issue, responder unavailable, malformed response). The specific error details are usually provided.
- **`skipped`**: The OCSP check was not performed. This can happen if:
    - The `--no-ocsp-check` flag was used.
    - The certificate does not contain an OCSP URI.
    - An OCSP check was not applicable for other reasons (e.g., for a CA certificate if only leaf certificate checks are configured).

---

## 🌐 Web Interface

![Screenshot of Web UI](screenshot_web.png)
*Example: HTML-based interactive certificate analysis (including OCSP status)*

- User-friendly web UI for interactive analysis
- Supports all CLI options via the browser
- Great for demos, teams, and non-CLI users!
- Includes a light/dark theme toggle

---

## ✨ Shell Completion

`check-tls` supports shell completion for bash, zsh, and fish. This helps you quickly fill in command-line options and arguments by pressing the `<Tab>` key.

To enable completion, you need to add a short script to your shell's configuration file. Use the command below for your specific shell (or create a file in your shell's config directory with the appropriate content, to make it persistent across sessions):

**Bash:**

Add the following line to your `~/.bashrc` or `~/.bash_profile`:

```sh
eval "$(check-tls --print-completion bash)"

**Zsh:**

Add the following line to your `~/.zshrc`:

```sh
eval "$(check-tls --print-completion zsh)"

**Fish:**

Add the following line to your `~/.config/fish/config.fish`:

```sh
check-tls --print-completion fish | source

--

## 🗂️ Project Structure

```text
check-tls/
├── src/
│   ├── main.py           # CLI entry point
│   ├── web_server.py     # Flask web server
│   ├── tls_checker.py    # Core logic
│   └── utils/            # Utility modules
│       ├── cert_utils.py
│       ├── crl_utils.py
│       ├── crtsh_utils.py
│       └── __init__.py
├── pyproject.toml
├── Dockerfile
├── README.md
└── ...
```

---

## ❓ FAQ

**Q: Can I use this tool without Python installed?**  
A: Yes! Use the Docker image for zero local dependencies.

**Q: How do I analyze multiple domains at once?**  
A: Just list them: `check-tls domain1.com domain2.com ...`

**Q: How do I get JSON or CSV output?**  
A: Use `-j file.json` or `-c file.csv`. Use `-` for stdout.

**Q: Is this safe for self-signed certificates?**  
A: Use the `-k` or `--insecure` flag to allow fetching certs without validation.

**Q: Can I run this as a web service?**  
A: Yes! Use `check-tls --server` or the Docker web mode.

**Q: Where are the logs?**  
A: By default, logs print to the console. Use `-l DEBUG` for more detail.

---

## 🛠️ Troubleshooting

**Problem:** `ModuleNotFoundError` or import errors after moving files

- **Solution:** Make sure you installed with `pip install .` from the project root, and that you run scripts via `check-tls ...` or `python -m src.main ...`.

**Problem:** `ERROR: ... does not appear to be a Python project: 'pyproject.toml' not found.`

- **Solution:** Ensure `pyproject.toml` is at the project root, not inside `src/`.

**Problem:** Web server runs but browser shows error

- **Solution:** Check the logs for Python exceptions, and ensure Flask is installed.

**Problem:** Docker build fails or can't find files

- **Solution:** Make sure your Dockerfile matches the new project structure and copies both `pyproject.toml` and the `src/` folder.

**Problem:** Can't bind to port 8000

- **Solution:** Make sure the port is not already in use, or use `-p` to specify a different port.

---

## 👩‍💻 Development

- All code is in `src/` (import as `from src.utils import ...`)
- Add new features as modules in `src/` or `src/utils/`
- Run tests and lint before submitting PRs
- For development, use `pip install -e .` to enable editable installs.

---

## 🤝 Contributing

Pull requests are welcome! Please open an issue to discuss major changes.

---

## 📜 License

MIT License © Grégoire Compagnon (obeone)

---

## 📦 Release & Publish

To publish a new version to PyPI, push a new release to GitHub. The GitHub Actions workflow will build and publish automatically if the release tag matches the version in `pyproject.toml`.

See `.github/workflows/publish-to-pypi.yaml` for details.
