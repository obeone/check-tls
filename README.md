# ✨ Check TLS Certificate ✨

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) <!-- Assuming MIT, update if different -->
[![Docker Hub](https://img.shields.io/badge/Docker%20Hub-obeoneorg%2Fcheck--tls-blue?logo=docker)](https://hub.docker.com/r/obeoneorg/check-tls)
[![GHCR.io](https://img.shields.io/badge/GHCR.io-obeone%2Fcheck--tls-blue?logo=github)](https://ghcr.io/obeone/check-tls)

A versatile Python tool to analyze TLS/SSL certificates for one or multiple domains, featuring profile detection, chain validation, and multiple output formats. Includes a handy web interface mode!

---

## 📚 Table of Contents

- [✨ Check TLS Certificate ✨](#-check-tls-certificate-)
  - [📚 Table of Contents](#-table-of-contents)
  - [🚀 Features](#-features)
  - [🛠️ Installation](#️-installation)
    - [Using Docker](#using-docker)
    - [Using pip](#using-pip)
  - [⚙️ Usage](#️-usage)
    - [Command Line Interface (CLI)](#command-line-interface-cli)
    - [Docker Container](#docker-container)
  - [🌐 Web Interface](#-web-interface)
  - [🤝 Contributing](#-contributing)
  - [📜 License](#-license)

---

## 🚀 Features

*   **Comprehensive Analysis**: Fetches leaf and intermediate certificates (via AIA).
*   **Full Validation**: Validates the certificate chain against the system's trust store.
*   **Profile Detection**: Identifies certificate usage profiles (e.g., `tlsserver`, `email`, `codeSigning`).
*   **SAN Extraction**: Lists Subject Alternative Names (SANs).
*   **Flexible Output**:
    *   Human-readable console output (with colors!).
    *   JSON format (`-j`/`--json`).
    *   CSV format (`-c`/`--csv`).
*   **Insecure Mode**: Option (`-k`/`--insecure`) to bypass SSL validation for fetching (useful for self-signed certs).
*   **Web Server Mode**: Run an interactive web UI (`-s`/`--server`) to analyze domains on the fly.
*   **Dockerized**: Available as ready-to-use Docker images.

---

## 🛠️ Installation

### Using Docker

This is the recommended method for quick use without installing dependencies locally.

Pull the image from Docker Hub or GitHub Container Registry:

```bash
# Docker Hub
docker pull obeoneorg/check-tls:latest

# GitHub Container Registry
docker pull ghcr.io/obeone/check-tls:latest
```

See the [Docker Usage](#docker-container) section for how to run the container.

### Using pip

If you prefer to install the script directly into your Python environment:

```bash
# Ensure you have Python 3.9+ and pip installed
git clone https://github.com/obeone/check-tls-bundle-final.git # Replace with your actual repo URL
cd check-tls-bundle-final
pip install .
```

---

## ⚙️ Usage

### Command Line Interface (CLI)

If installed via pip, the script is available as `check-tls`.

```bash
check-tls [OPTIONS] domain1 [domain2 ...]
```

**Options:**

*   `domain...`: One or more domains to analyze.
*   `-j, --json FILE`: Output JSON report to FILE (`-` for stdout).
*   `-c, --csv FILE`: Output CSV report to FILE (`-` for stdout).
*   `-m, --mode MODE`: Analysis mode: `simple` (leaf only) or `full` (fetch intermediates, default).
*   `-l, --loglevel LEVEL`: Set log level (e.g., `DEBUG`, `INFO`, `WARN`, `ERROR`). Default: `WARN`.
*   `-k, --insecure`: Allow fetching certificates without SSL validation.
*   `-s, --server`: Run as an HTTP server with a web interface.
*   `-p, --port PORT`: Specify server port (default: 8000).

**Examples:**

```bash
# Analyze a single domain with default settings (full mode)
check-tls example.com

# Analyze multiple domains and output to JSON file
check-tls google.com github.com -j report.json

# Analyze in simple mode, ignoring SSL errors, and print CSV to stdout
check-tls self-signed.local -m simple -k -c -

# Run the web server on port 8080
check-tls -s -p 8080
```

### Docker Container

```bash
# Analyze example.com using the Docker Hub image
docker run --rm obeoneorg/check-tls:latest example.com

# Analyze multiple domains and output JSON using the GHCR image
docker run --rm ghcr.io/obeone/check-tls:latest google.com github.com -j -

# Run the web server, mapping container port 8000 to host port 8080
docker run --rm -p 8080:8000 obeoneorg/check-tls:latest -s
# Then access http://localhost:8080 in your browser
```

---

## 🌐 Web Interface

When run with the `-s` or `--server` flag (either directly or via Docker), `check-tls` starts a simple Flask web server. Access it via your browser (e.g., `http://localhost:8000` or the port specified with `-p` or mapped in Docker).

Enter domains separated by spaces or commas, choose whether to ignore SSL errors, and click "Analyze". The results will be displayed on the page.

![Web Interface Screenshot](placeholder.png)  <!-- TODO: Add a real screenshot -->

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues on the [GitHub repository](https://github.com/obeone/check-tls-bundle-final). <!-- Replace with your actual repo URL -->

---

## 📜 License

This project is licensed under the MIT License. Author: Grégoire Compagnon [obeone](https://github.com/obeone).
