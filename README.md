# ✨ Check TLS Certificate ✨

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI Version](https://img.shields.io/pypi/v/check-tls.svg)](https://pypi.org/project/check-tls/)
[![Docker Hub](https://img.shields.io/badge/Docker%20Hub-obeoneorg%2Fcheck--tls-blue?logo=docker)](https://hub.docker.com/r/obeoneorg/check-tls)
[![GHCR.io](https://img.shields.io/badge/GHCR.io-obeone%2Fcheck--tls-blue?logo=github)](https://ghcr.io/obeone/check-tls)

A powerful, developer-friendly Python tool to analyze TLS/SSL certificates for any domain.

---

## 📚 Table of Contents

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
- [🌐 Web Interface](#-web-interface)
- [🗂️ Project Structure](#️-project-structure)
- [❓ FAQ](#-faq)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [👩‍💻 Development](#-development)
- [🤝 Contributing](#-contributing)
- [📜 License](#-license)
- [📦 Release & Publish](#-release--publish)

---

## 🚀 Features

- **Comprehensive Analysis**: Fetches leaf & intermediate certificates (AIA fetching)
- **Chain Validation**: Validates against system trust store
- **Profile Detection**: Detects usage profiles (server, email, code signing, etc.)
- **CRL & Transparency**: Checks CRL status and certificate transparency logs
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
*Example: Command-line output for analyzing a domain*

Analyze a domain:

```sh
check-tls example.com
```

Analyze multiple domains, output JSON:

```sh
check-tls google.com github.com -j report.json
```

Human-readable output (default), or use `-j` for JSON and `-c` for CSV.

**Key options:**

- `-j, --json FILE`   Output JSON (use "-" for stdout)
- `-c, --csv FILE`    Output CSV (use "-" for stdout)
- `-k, --insecure`    Allow self-signed certs
- `-s, --server`      Launch web UI
- `-p, --port`        Web server port
- `--no-transparency` Skip transparency check
- `--no-crl-check`    Skip CRL check

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

## 🌐 Web Interface

![Screenshot of Web UI](screenshot_web.png)
*Example: HTML-based interactive certificate analysis*

- User-friendly web UI for interactive analysis
- Supports all CLI options via the browser
- Great for demos, teams, and non-CLI users!

---

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
├── setup.py
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

**Problem:** `ERROR: ... does not appear to be a Python project: neither 'setup.py' nor 'pyproject.toml' found.`

- **Solution:** Ensure `setup.py` is at the project root, not inside `src/`.

**Problem:** Web server runs but browser shows error

- **Solution:** Check the logs for Python exceptions, and ensure Flask is installed.

**Problem:** Docker build fails or can't find files

- **Solution:** Make sure your Dockerfile matches the new project structure and copies both `setup.py` and the `src/` folder.

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

To publish a new version to PyPI, push a new release to GitHub. The GitHub Actions workflow will build and publish automatically if the release tag matches the version in `setup.py`.

See `.github/workflows/publish-to-pypi.yaml` for details.
