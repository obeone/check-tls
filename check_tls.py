# -*- coding: utf-8 -*-
#!/usr/bin/env python3
# MIT License
#
# Author: Grégoire Compagnon (obeone) (https://github.com/obeone)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
Analyze TLS certificates from one or multiple domains with profile detection and full validation.

Modes:
    - full   : fetch the leaf certificate and attempt to complete the chain using AIA fetching (default)

Usage:
    python3 check_tls_en.py [options] domain1 [domain2 ...]

Options:
    -j, --json FILE         Output JSON report to FILE (use '-' for stdout)
    -c, --csv FILE          Output CSV report to FILE (use '-' for stdout)
    -m, --mode MODE         Choose mode: 'simple' or 'full' (default: full)
    -l, --loglevel LEVEL    Set log level (default: WARN)
    -k, --insecure          Allow fetching certificates without validation (self-signed)
    -s, --server            Run as HTTP server with web interface
    -p, --port PORT         Specify server port (default: 8000)
"""

import argparse
import json
import csv
import socket
import ssl
import sys
import os
import subprocess
import logging
from typing import List, Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID
import coloredlogs
import urllib.request
from flask import Flask, render_template_string, request, jsonify


logger = logging.getLogger("certcheck")

def fetch_leaf_certificate(domain: str, insecure: bool = False) -> x509.Certificate:
    """
    Fetch the leaf (end-entity) TLS certificate from a given domain.

    Args:
        domain (str): The domain to connect to (port 443 is used).
        insecure (bool): If True, disables SSL verification (allows self-signed/invalid certs).

    Returns:
        x509.Certificate: The leaf certificate as a cryptography.x509 object.

    Raises:
        Exception: If the certificate cannot be fetched or parsed.

    Notes:
        Uses the SNI extension and can optionally skip SSL validation.
    """
    logger.debug(f"Connecting to {domain} to fetch the leaf certificate...")
    context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
        if der_cert is None:
            raise ValueError("No certificate received from server.")
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        logger.info(f"Fetched leaf certificate from {domain}")
        return cert
    except Exception as e:
        if not insecure:
            logger.error(f"Failed to fetch certificate from {domain} (invalid SSL). Use -k/--insecure to ignore SSL errors.")
        else:
            logger.exception(f"Failed to fetch certificate from {domain}: {e}")
        raise

def fetch_intermediate_certificates(cert: x509.Certificate) -> List[x509.Certificate]:
    """
    Fetch intermediate certificates referenced by the Authority Information Access (AIA) extension.

    Args:
        cert (x509.Certificate): The certificate whose intermediates are to be fetched.

    Returns:
        List[x509.Certificate]: A list of intermediate certificates (may be empty).

    Notes:
        Only fetches intermediates via HTTP(s) URLs found in the AIA extension.
        If the extension is missing or fetching fails, returns an empty list.
    """
    intermediates = []
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        # Use private _descriptions attribute for compatibility with cryptography
        for desc in getattr(aia, "_descriptions", []):
            if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                url = desc.access_location.value
                logger.info(f"Fetching intermediate certificate from {url}")
                with urllib.request.urlopen(url, timeout=10) as response:
                    intermediate_der = response.read()
                    intermediate_cert = x509.load_der_x509_certificate(intermediate_der, default_backend())
                    intermediates.append(intermediate_cert)
    except x509.ExtensionNotFound:
        logger.warning("No AIA extension found to fetch intermediates.")
    except Exception as e:
        logger.warning(f"Failed to fetch intermediate certificates: {e}")
    return intermediates

def validate_certificate_chain(domain: str) -> bool:
    """
    Validate the SSL/TLS certificate chain for a given domain using the system's trust store.

    Args:
        domain (str): The domain to validate.

    Returns:
        bool: True if the certificate chain is valid, False otherwise.

    Notes:
        This function does not return the certificate itself, only the validation result.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                ssock.getpeercert()
        logger.info(f"SSL validation OK for {domain}")
        return True
    except ssl.SSLError as e:
        logger.warning(f"SSL validation FAILED for {domain}: {e}")
        return False
    except Exception as e:
        logger.error(f"Connection error with {domain}: {e}")
        return False

def detect_profile(cert: x509.Certificate) -> str:
    """
    Detect the intended usage profile of a certificate based on its extensions.

    Args:
        cert (x509.Certificate): The certificate to analyze.

    Returns:
        str: A string describing the detected profile (e.g., 'tlsserver', 'email', 'codeSigning', or legacy).

    Notes:
        Relies on Key Usage and Extended Key Usage extensions.
        Returns a legacy/incomplete profile if expected extensions are missing.
    """
    try:
        key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        ext_key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        # Use private _usages attribute for compatibility with cryptography
        usages = [eku.dotted_string for eku in getattr(ext_key_usage, "_usages", [])]
        if ExtendedKeyUsageOID.SERVER_AUTH.dotted_string in usages:
            if getattr(key_usage, "digital_signature", False) and getattr(key_usage, "key_encipherment", False):
                return "tlsserver"
        elif ExtendedKeyUsageOID.EMAIL_PROTECTION.dotted_string in usages:
            return "email"
        elif ExtendedKeyUsageOID.CODE_SIGNING.dotted_string in usages:
            return "codeSigning"
        else:
            return "subscriber (legacy or flexible)"
        # Fallback in case no return above
        return "unknown"
    except x509.ExtensionNotFound:
        logger.warning("Missing expected X509 extensions")
        return "subscriber (legacy or incomplete)"

def extract_san(cert: x509.Certificate) -> List[str]:
    """
    Extract the Subject Alternative Names (SANs) from a certificate.

    Args:
        cert (x509.Certificate): The certificate to extract SANs from.

    Returns:
        List[str]: A list of DNS names found in the SAN extension, or an empty list if not present.
    """
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        # ext.value is a SubjectAlternativeName object
        # Use private _general_names attribute for compatibility with cryptography
        return [name.value for name in getattr(ext.value, "_general_names", []) if isinstance(name, x509.DNSName)]
    except x509.ExtensionNotFound:
        return []

def analyze_certificates(domain: str, mode: str = "full", insecure: bool = False) -> dict:
    """
    Analyze the TLS certificates for a given domain, including validation and profile detection.

    Args:
        domain (str): The domain to analyze.
        mode (str): 'full' to fetch intermediates, 'simple' for leaf only.
        insecure (bool): If True, disables SSL verification for fetching.

    Returns:
        dict: A dictionary containing the domain, SSL validity, and a list of certificate details.

    Notes:
        Each certificate entry includes subject, issuer, validity, profile, and SANs.
    """
    result = {
        "domain": domain,
        "valid_ssl": validate_certificate_chain(domain),
        "certificates": []
    }
    try:
        leaf_cert = fetch_leaf_certificate(domain, insecure=insecure)
    except Exception:
        return result

    certs = [leaf_cert]
    if mode == "full":
        intermediates = fetch_intermediate_certificates(leaf_cert)
        certs.extend(intermediates)

    for _, cert in enumerate(certs):
        cert_data = {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "profile": detect_profile(cert),
            "san": extract_san(cert)
        }
        result["certificates"].append(cert_data)
    return result

def run_analysis(domains: List[str], output_json: Optional[str] = None, output_csv: Optional[str] = None, mode: str = "full", insecure: bool = False):
    """
    Run the certificate analysis for a list of domains and output the results in JSON, CSV, or human-readable format.

    Args:
        domains (List[str]): List of domains to analyze.
        output_json (Optional[str]): Path to output JSON file, or '-' for stdout.
        output_csv (Optional[str]): Path to output CSV file, or '-' for stdout.
        mode (str): 'full' or 'simple' analysis mode.
        insecure (bool): If True, disables SSL verification for fetching.

    Returns:
        None

    Notes:
        Outputs results to the specified files or prints to stdout if no output file is given.
    """
    results = []
    for domain in domains:
        logger.info(f"Analyzing domain: {domain}")
        analysis = analyze_certificates(domain, mode, insecure)
        results.append(analysis)

    if output_json:
        out = sys.stdout if output_json == "-" else open(output_json, "w")
        json.dump(results, out, indent=2)
        if out is not sys.stdout:
            out.close()
            logger.info(f"JSON report written to {output_json}")

    if output_csv:
        out = sys.stdout if output_csv == "-" else open(output_csv, "w", newline='')
        writer = csv.writer(out)
        writer.writerow(["Domain", "Cert#", "Subject", "Issuer", "NotBefore", "NotAfter", "Profile", "SANs"])
        for result in results:
            for i, cert in enumerate(result["certificates"]):
                writer.writerow([
                    result["domain"], i + 1, cert["subject"], cert["issuer"], cert["not_before"], cert["not_after"], cert["profile"], ",".join(cert["san"])
                ])
        if out is not sys.stdout:
            out.close()
            logger.info(f"CSV report written to {output_csv}")

    if not output_json and not output_csv:
        for result in results:
            print(f"\n\033[1;34m[ Domain: {result['domain']} ]\033[0m")
            ssl_status = '\033[92m✔️ Valid SSL\033[0m' if result['valid_ssl'] else '\033[91m❌ Invalid SSL\033[0m'
            print(f"  Status   : {ssl_status}\n")
            for i, cert in enumerate(result['certificates']):
                print(f"  \033[1mCertificate {i+1}:\033[0m")
                print(f"    \033[93mSubject:\033[0m {cert['subject']}")
                print(f"    \033[93mIssuer:\033[0m  {cert['issuer']}")
                print(f"    \033[93mValid:\033[0m   {cert['not_before']} → {cert['not_after']}")
                print(f"    \033[93mProfile:\033[0m {cert['profile']}")
                print(f"    \033[93mSANs:\033[0m    {', '.join(cert['san']) if cert['san'] else 'None'}\n")

HTML_TEMPLATE = """
<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>
<title>TLS Analysis</title>
</head>
<body class='bg-light'>
<div class='container py-5'>
<h1 class='mb-4'>🔒 TLS Analysis</h1>
<form method='post' class='mb-5'>
<div class='mb-3'>
<label for='domains' class='form-label'>Domains to analyze:</label>
<input type='text' class='form-control' id='domains' name='domains' placeholder='e.g. example.com test.org'>
</div>
<div class='form-check mb-3'>
<input class='form-check-input' type='checkbox' id='insecure' name='insecure' value='true'>
<label class='form-check-label' for='insecure'>
Ignore SSL errors (insecure)
</label>
</div>
<button type='submit' class='btn btn-primary'>Analyze</button>
</form>
{% if results %}
{% for result in results %}
<div class='card mb-4'>
<div class='card-header d-flex justify-content-between'>
<strong>{{ result.domain }}</strong>
<span class='badge {% if result.valid_ssl %}bg-success{% else %}bg-danger{% endif %}'>
{% if result.valid_ssl %}Valid{% else %}Invalid{% endif %}
</span>
</div>
<div class='card-body'>
{% for cert in result.certificates %}
<table class='table table-bordered'>
<tr><th>Subject</th><td>{{ cert.subject }}</td></tr>
<tr><th>Issuer</th><td>{{ cert.issuer }}</td></tr>
<tr><th>Validity</th><td>{{ cert.not_before }} → {{ cert.not_after }}</td></tr>
<tr><th>Profile</th><td>{{ cert.profile }}</td></tr>
<tr><th>SANs</th><td>{{ cert.san | join(", ") }}</td></tr>
</table>
{% endfor %}
</div>
</div>
{% endfor %}
{% endif %}
</div>
</body>
</html>
"""

def run_server(args):
    """
    Run the Flask web server for interactive TLS analysis.

    Args:
        args: Parsed command-line arguments (from argparse).

    Returns:
        None

    Notes:
        Provides a web interface for users to submit domains and view results.
        Supports both HTML and JSON output.
    """
    app = Flask(__name__)

    @app.route('/', methods=['GET', 'POST'])
    def index():
        """
        Handle the main page for domain submission and result display.

        Returns:
            Rendered HTML template or JSON response.
        """
        results = None
        if request.method == 'POST':
            raw = request.form.get('domains', '')
            domains = [d.strip() for d in raw.replace(',', ' ').split() if d.strip()]
            insecure_flag = request.form.get('insecure') == 'true'
            cmd = [sys.executable, os.path.abspath(__file__), '--json', '-', '--mode', args.mode]
            # Combine server-level insecure flag with request-level flag
            if args.insecure or insecure_flag:
                cmd.append('--insecure')
            cmd.extend(domains)
            output = subprocess.check_output(cmd)
            results = json.loads(output)

        if request.accept_mimetypes.best == 'application/json':
            return jsonify(results or [])

        return render_template_string(HTML_TEMPLATE, results=results)

    app.run(host='0.0.0.0', port=args.port)

def main():
    """
    Entry point for the script. Parses command-line arguments and runs the appropriate mode
    (batch analysis or web server).

    Command-line options:
        domains: List of domains to analyze.
        -j/--json: Output JSON file (or '-' for stdout).
        -c/--csv: Output CSV file (or '-' for stdout).
        -m/--mode: Analysis mode ('simple' or 'full').
        -l/--loglevel: Logging level.
        -k/--insecure: Allow fetching certificates without SSL verification.
        -s/--server: Run as HTTP server.
        -p/--port: Server port (default: 8000).
    """
    parser = argparse.ArgumentParser(description="Analyze TLS certificates with profile detection.")
    parser.add_argument("domains", nargs="*", help="List of domains to check.")
    parser.add_argument("-j", "--json", help="Output JSON report to specified file ('-' for stdout).")
    parser.add_argument("-c", "--csv", help="Output CSV report to specified file ('-' for stdout).")
    parser.add_argument("-m", "--mode", choices=["simple", "full"], default="full", help="Choose analysis mode: simple or full.")
    parser.add_argument("-l", "--loglevel", default="WARN", help="Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).")
    parser.add_argument("-k", "--insecure", action="store_true", help="Allow fetching certificates without SSL verification.")
    parser.add_argument("-s", "--server", action="store_true", help="Run as HTTP server with web interface.")
    parser.add_argument("-p", "--port", type=int, default=8000, help="Specify server port (default: 8000).")

    args = parser.parse_args()

    loglevel = getattr(logging, args.loglevel.upper(), logging.WARNING)
    coloredlogs.install(level=loglevel, logger=logger, fmt='%(asctime)s [%(levelname)s] %(message)s')

    if args.server:
        run_server(args)
        sys.exit(0)

    run_analysis(args.domains, output_json=args.json, output_csv=args.csv, mode=args.mode, insecure=args.insecure)

if __name__ == "__main__":
    main()
