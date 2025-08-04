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
    - [Command Line](#command-line)
    - [Web UI](#web-ui)
  - [🖥️ REST API Usage](#️-rest-api-usage)
    - [Analyze Domains (POST /api/analyze)](#analyze-domains-post-apianalyze)
      - [Example curl Request](#example-curl-request)
      - [Example JSON Response](#example-json-response)
  - [OCSP Status Explained](#ocsp-status-explained)
  - [🌐 Web Interface](#-web-interface)
  - [✨ Shell Completion](#-shell-completion)
  - [🗂️ Project Structure](#️-project-structure)
  - [❓ FAQ](#-faq)
  - [🛠️ Troubleshooting](#️-troubleshooting)
  - [👩‍💻 Development](#-development)
  - [🤝 Contributing](#-contributing)
  - [📜 License](#-license)
  - [📦 Release \& Publish](#-release--publish)

---

## 🚀 Features

- **Comprehensive Analysis**: Fetches leaf & intermediate certificates using Authority Information Access (AIA).
- **Chain Validation**: Validates the certificate chain against the system's default trust store.
- **Profile Detection**: Detects certificate profiles like TLS Server, Code Signing, S/MIME, etc., based on Key Usage and Extended Key Usage extensions.
- **Revocation Checks**:
  - **OCSP**: Performs Online Certificate Status Protocol (OCSP) checks.
  - **CRL**: Checks Certificate Revocation Lists (CRL).
- **DNS CAA Check**: Displays DNS Certification Authority Authorization (CAA) records for the domain.
- **Certificate Transparency**: Queries `crt.sh` for Certificate Transparency logs.
- **Flexible Output**: Human-readable (color-coded), JSON, or CSV formats.
- **Web UI**: Interactive browser-based analysis via a built-in Flask server.
- **REST API**: Programmatic access for seamless integration into other tools.
- **Dockerized**: Ready to use with zero local setup via Docker Hub or GHCR.

---

## 🛠️ Installation

### Recommended: With pipx

`pipx` installs CLI tools in isolated environments, which is the safest way to install Python applications.

```sh
pipx install check-tls
```

### Alternative: With pip

```sh
pip install check-tls
```

### With Docker

Pull the latest image from Docker Hub or GHCR:

```sh
# From Docker Hub
docker pull obeoneorg/check-tls:latest

# Or from GHCR.io
docker pull ghcr.io/obeone/check-tls:latest
```

**Running the Container**

You can run the tool in either CLI mode or as a web server.

**1. CLI Mode**

To analyze a domain, pass it as a command to the container:

```sh
docker run --rm obeoneorg/check-tls:latest example.com
```

To output to a file on your host machine, mount a volume:

```sh
# Create a reports directory first: mkdir -p reports
docker run --rm -v "$(pwd)/reports:/app/reports" \
  obeoneorg/check-tls:latest example.com -j /app/reports/report.json
```

**2. Web Server Mode**

To run the interactive web UI, use the `--server` flag and map the port:

```sh
docker run --rm -p 8000:8000 obeoneorg/check-tls:latest --server
```

The web interface will be available at <http://localhost:8000>.

---

## ⚙️ Usage

### Command Line

![Screenshot of CLI Output](screenshot_cli.png)
*Example: Command-line output for analyzing a domain (including OCSP status)*

Analyze a single domain:

```sh
check-tls example.com
```

Analyze a domain with a specific port:

```sh
# The port in the URL overrides the default or --connect-port
check-tls https://example.net:9000
```

Analyze multiple domains and output to a JSON file:

```sh
check-tls google.com https://github.com:443 -j report.json
```

The CLI provides human-readable output by default. Use `-j` for JSON and `-c` for CSV. When analyzing multiple domains, a progress indicator will be displayed.

**Key Options:**

- `-j, --json FILE`: Output JSON to a file (use "-" for stdout).
- `-c, --csv FILE`: Output CSV to a file (use "-" for stdout).
- `-P, --connect-port PORT`: Port for TLS analysis (default: 443). Overridden by port in domain/URL.
- `-m, --mode [simple|full]`: Analysis mode. `simple` checks the leaf certificate only; `full` fetches intermediates (default).
- `-l, --loglevel LEVEL`: Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
- `-k, --insecure`: Allow self-signed or invalid certificates.
- `-s, --server`: Launch the web UI.
- `-p, --port PORT`: Web server port for the UI (default: 8000).
- `--no-transparency`: Skip certificate transparency check.
- `--no-crl-check`: Skip CRL check.
- `--no-ocsp-check`: Disable OCSP revocation check.
- `--no-caa-check`: Disable DNS CAA check.

### Web UI

To launch the interactive web interface, use the `--server` flag:

```sh
check-tls --server
```

Then, open <http://localhost:8000> in your browser.

---

## 🖥️ REST API Usage

The tool provides a REST API for programmatic analysis. When launched with `--server`, the API is available.

### Analyze Domains (POST /api/analyze)

- **Endpoint:** `/api/analyze`
- **Method:** `POST`
- **Content-Type:** `application/json`

**Request Body:**

- `domains` (array of strings, required): List of domains to analyze (e.g., `["example.com", "google.com:443"]`).
- `connect_port` (integer, optional): Default port to connect to if not specified in the domain string. Defaults to 443.
- `insecure` (boolean, optional): Allow insecure (self-signed) certificates.
- `no_transparency` (boolean, optional): Skip certificate transparency check.
- `no_crl_check` (boolean, optional): Disable CRL check.
- `no_ocsp_check` (boolean,optional): Disable OCSP check.
- `no_caa_check` (boolean, optional): Disable CAA check.

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
    "domain": "example.com:443",
    "status": "completed",
    "analysis_timestamp": "2025-04-26T08:30:00+00:00",
    "connection_health": { ... },
    "validation": { ... },
    "certificates": [ ... ],
    "crl_check": { ... },
    "transparency": { ... },
    "ocsp_check": { ... },
    "caa_check": { ... }
  }
]
```

---

## OCSP Status Explained

The tool provides the following OCSP statuses for the leaf certificate:

- **`good`**: The certificate is valid according to its OCSP responder.
- **`revoked`**: The certificate has been revoked.
- **`unknown`**: The OCSP responder does not have status information for the certificate.
- **`error`**: An error occurred during the OCSP check (e.g., network issue, responder unavailable).
- **`no_ocsp_url`**: The certificate does not contain an OCSP URI.
- **`skipped`**: The OCSP check was disabled or not applicable.

---

## 🌐 Web Interface

![Screenshot of Web UI](screenshot_web.png)
*Example: HTML-based interactive certificate analysis (including OCSP status)*

- User-friendly web UI for interactive analysis.
- Supports all CLI options via the browser.
- Great for demos, teams, and non-CLI users!
- Includes a light/dark theme toggle.

---

## ✨ Shell Completion

`check-tls` supports shell completion for bash, zsh, and fish. To enable it, add the appropriate command to your shell's configuration file (`~/.bashrc`, `~/.zshrc`, or `~/.config/fish/config.fish`).

**Bash:**

```sh
eval "$(check-tls --print-completion bash)"
```

**Zsh:**

```sh
eval "$(check-tls --print-completion zsh)"
```

**Fish:**

```sh
check-tls --print-completion fish | source
```

---

## 🗂️ Project Structure

The project follows the standard `src` layout for packaging.

```text
check-tls/
├── src/
│   └── check_tls/
│       ├── __init__.py
│       ├── main.py           # CLI entry point
│       ├── tls_checker.py    # Core analysis logic
│       ├── web_server.py     # Flask web server and API
│       ├── static/           # CSS/JS for web UI
│       ├── templates/        # HTML templates for web UI
│       └── utils/            # Utility modules
│           ├── __init__.py
│           ├── cert_utils.py
│           ├── crl_utils.py
│           ├── crtsh_utils.py
│           ├── dns_utils.py
│           └── ocsp_utils.py
├── pyproject.toml            # Project metadata and dependencies
├── Dockerfile
├── LICENSE
└── README.md
```

---

## ❓ FAQ

**Q: What's the difference between `--port` and `--connect-port`?**  
A: `--port` (or `-p`) specifies the port for the **web server UI** (`--server` mode). `--connect-port` (or `-P`) specifies the default port for the **TLS connection** to the target domain.

**Q: What does "No CDP" or "No OCSP URL" mean?**  
A: This means the certificate does not contain a URL for its Certificate Revocation List (CRL) or an OCSP responder. This is common and not necessarily an error, but it prevents the tool from performing that specific revocation check.

**Q: How do I analyze a server that uses a self-signed certificate?**  
A: Use the `-k` or `--insecure` flag. This tells the tool to connect without validating the certificate against a trusted authority, which is necessary for self-signed certs.

**Q: Can I use this tool without Python installed?**  
A: Yes! The Docker image provides a self-contained environment with all dependencies. See the "With Docker" section for instructions.

**Q: How do I get JSON or CSV output?**  
A: Use `-j file.json` or `-c file.csv`. Use `-` as the filename to print to standard output.

---

## 🛠️ Troubleshooting

**Problem: `ssl.SSLCertVerificationError`**

- **Cause:** The certificate chain could not be validated against your system's trust store. This is expected for self-signed certificates or if an intermediate certificate is missing.
- **Solution:** If you trust the server, use the `-k` or `--insecure` flag to bypass validation. For production systems, this error indicates a misconfiguration that should be fixed.

**Problem: Connection Errors (`Connection refused`, `timed out`, `gaierror`)**

- **Cause:** These are network-level issues.
  - `Connection refused`: The server is not listening on the specified port.
  - `timed out`: The server is unreachable, or a firewall is blocking the connection.
  - `gaierror` or `Name or service not known`: The domain name could not be resolved by DNS.
- **Solution:** Verify the domain name and port. Check for firewall rules and ensure the server is running and accessible from your location.

**Problem: `ModuleNotFoundError` or import errors.**

- **Solution:** Ensure the package was installed correctly (e.g., `pip install .`). When running from source, use `python -m check_tls.main ...`.

**Problem: Shell completion isn't working.**

- **Solution:** Ensure you have sourced the completion script in your shell's configuration file (`.bashrc`, `.zshrc`, etc.) and have restarted your shell. For Fish, the completion file must be placed in the correct directory.

**Problem: Docker container exits immediately.**

- **Cause:** You need to provide a command to the container.
- **Solution:** Specify a domain to analyze or a flag like `--server`. For example: `docker run --rm obeoneorg/check-tls:latest example.com`.

---

## 👩‍💻 Development

- All source code is located in `src/check_tls/`.
- Imports should be relative to the package, e.g., `from check_tls.utils import ...`.
- For development, use an editable install: `pip install -e .`. This allows you to test changes without reinstalling.
- To run the application from source, use `python -m check_tls.main [OPTIONS]`.
- Run tests and linting before submitting a pull request.

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

---

## 📜 License

MIT License © Grégoire Compagnon (obeone)

---

## 📦 Release & Publish

To publish a new version to PyPI, create a new release on GitHub. The GitHub Actions workflow will build and publish the package automatically if the release tag matches the version in `pyproject.toml`.

See `.github/workflows/publish-to-pypi.yaml` for details.
