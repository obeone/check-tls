# -*- coding: utf-8 -*-
#!/usr/bin/env python3
# MIT License
#
# Author: Grégoire Compagnon (obeone) (https://github.com/obeone)
# Modifications by Gemini
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
Analyze TLS certificates from one or multiple domains with profile detection,
full validation, cryptographic details, connection health (using Python ssl),
CRL checks (default ON), and certificate transparency checks.

Modes:
    - full   : fetch the leaf certificate and attempt to complete the chain using AIA fetching (default)

Usage:
    python3 check_tls.py [options] domain1 [domain2 ...]

Options:
    -j, --json FILE         Output JSON report to FILE (use '-' for stdout)
    -c, --csv FILE          Output CSV report to FILE (use '-' for stdout)
    -m, --mode MODE         Choose mode: 'simple' or 'full' (default: full)
    -l, --loglevel LEVEL    Set log level (default: WARN)
    -k, --insecure          Allow fetching certificates without validation (self-signed)
    -s, --server            Run as HTTP server with web interface
    -p, --port PORT         Specify server port (default: 8000)
    --no-transparency       Skip crt.sh certificate transparency check
    --no-crl-check          Disable CRL check for the leaf certificate (experimental)
"""

import argparse
import json
import csv
import socket
import ssl
import sys
import os
# import subprocess # No longer needed
import logging
import datetime
from datetime import timezone
import hashlib
# import re # No longer needed
from typing import List, Optional, Dict, Any, Tuple
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID, NameOID, CRLEntryExtensionOID
import coloredlogs
import urllib.request
from urllib.parse import quote_plus, urlparse
from flask import Flask, render_template_string, request, jsonify, current_app


# --- Configuration ---
CRTSH_TIMEOUT = 15  # Timeout for crt.sh queries
CRL_TIMEOUT = 10  # Timeout for downloading CRL files

# --- Logging ---
logger = logging.getLogger("certcheck")

# --- Helper Functions ---

def calculate_days_remaining(cert: x509.Certificate) -> int:
    """Calculates the number of days until the certificate expires."""
    now_utc = datetime.datetime.now(timezone.utc)
    expiry_utc = cert.not_valid_after_utc
    if expiry_utc.tzinfo is None:
        expiry_utc = expiry_utc.replace(tzinfo=timezone.utc)
    delta = expiry_utc - now_utc
    return delta.days


def get_sha256_fingerprint(cert: x509.Certificate) -> str:
    """Calculates the SHA-256 fingerprint of the certificate."""
    return cert.fingerprint(hashes.SHA256()).hex()


def get_public_key_details(cert: x509.Certificate) -> Tuple[str, Optional[int]]:
    """Extracts the public key algorithm and size."""
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = public_key.curve.name if hasattr(
            public_key.curve, 'name') else 'Unknown Curve'
        return f"ECDSA ({curve_name})", public_key.curve.key_size
    elif isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    else:
        try:
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            algo_name = pem.decode().split('\n')[0].replace(
                '-----BEGIN PUBLIC KEY-----', '').strip()
            return algo_name if algo_name else "Unknown", None
        except Exception:
            return "Unknown", None


def get_signature_algorithm(cert: x509.Certificate) -> str:
    """Extracts the signature algorithm OID name."""
    try:
        sig_algo_oid = cert.signature_algorithm_oid
        sig_hash_algo = cert.signature_hash_algorithm
        oid_name = sig_algo_oid._name if hasattr(
            sig_algo_oid, '_name') else sig_algo_oid.dotted_string
        hash_name = sig_hash_algo.name if sig_hash_algo and hasattr(
            sig_hash_algo, 'name') else None

        if hash_name and oid_name.lower().endswith(hash_name.lower()):
            return oid_name
        elif hash_name:
            oid_simple = oid_name.replace(
                'Encryption', '').replace('Signature', '').strip()
            return f"{hash_name.lower()}-with-{oid_simple}"
        return oid_name
    except Exception as e:
        logger.warning(f"Could not determine signature algorithm details: {e}")
        try:
            return cert.signature_algorithm_oid.dotted_string
        except Exception:
            return "Unknown"


def has_scts(cert: x509.Certificate) -> bool:
    """Checks if the certificate has Signed Certificate Timestamps (SCTs)."""
    sct_oid = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
    try:
        cert.extensions.get_extension_for_oid(sct_oid)
        return True
    except x509.ExtensionNotFound:
        return False
    except Exception as e:
        logger.warning(f"Error checking for SCT extension: {e}")
        return False


def query_crtsh(domain: str) -> Optional[List[Dict[str, Any]]]:
    """Queries crt.sh for certificates related to the domain."""
    url = f"https://crt.sh/?q={quote_plus(domain)}&output=json"
    logger.info(f"Querying crt.sh for {domain}")
    try:
        req = urllib.request.Request(
            url, headers={'User-Agent': 'Python-CertCheck/1.3'}) # Updated UA
        with urllib.request.urlopen(req, timeout=CRTSH_TIMEOUT) as response:
            if response.status == 200:
                data = json.loads(response.read())
                unique_certs = {entry['min_cert_id']
                    : entry for entry in data}.values()
                logger.info(
                    f"Found {len(unique_certs)} unique certificate entries on crt.sh for {domain}")
                return list(unique_certs)
            else:
                logger.warning(
                    f"crt.sh query for {domain} failed with status {response.status}")
                return None
    except urllib.error.URLError as e:
        logger.warning(f"Could not connect to crt.sh for {domain}: {e}")
        return None
    except json.JSONDecodeError as e:
        logger.warning(
            f"Failed to parse crt.sh JSON response for {domain}: {e}")
        return None
    except socket.timeout:
        logger.warning(f"Connection to crt.sh timed out for domain {domain}")
        return None
    except Exception as e:
        logger.warning(
            f"An unexpected error occurred during crt.sh query for {domain}: {e}")
        return None

# --- START: CRL Check Functions ---

def download_crl(url: str) -> Optional[bytes]:
    """Downloads a CRL file from a given URL."""
    logger.debug(f"Attempting to download CRL from: {url}")
    try:
        req = urllib.request.Request(
            url, headers={'User-Agent': 'Python-CertCheck/1.3'}) # Updated UA
        with urllib.request.urlopen(req, timeout=CRL_TIMEOUT) as response:
            if response.status == 200:
                crl_data = response.read()
                logger.info(f"Successfully downloaded CRL from {url} ({len(crl_data)} bytes)")
                return crl_data
            else:
                logger.warning(f"Failed to download CRL from {url}, status code: {response.status}")
                return None
    except urllib.error.URLError as e:
        logger.warning(f"Failed to download CRL from {url}: {e.reason}")
        return None
    except socket.timeout:
        logger.warning(f"Timeout downloading CRL from {url}")
        return None
    except Exception as e:
        logger.warning(f"Unexpected error downloading CRL from {url}: {e}")
        return None


def parse_crl(crl_data: bytes) -> Optional[x509.CertificateRevocationList]:
    """Parses CRL data (tries DER first, then PEM)."""
    try:
        crl = x509.load_der_x509_crl(crl_data, default_backend())
        logger.debug("Parsed CRL as DER")
        return crl
    except ValueError:
        logger.debug("Failed to parse CRL as DER, trying PEM...")
        try:
            crl = x509.load_pem_x509_crl(crl_data, default_backend())
            logger.debug("Parsed CRL as PEM")
            return crl
        except ValueError as e:
            logger.warning(f"Failed to parse CRL data as DER or PEM: {e}")
            return None
    except Exception as e:
        logger.error(f"Unexpected error parsing CRL data: {e}")
        return None


def check_crl(cert: x509.Certificate) -> Dict[str, Any]:
    """
    Checks the revocation status of a certificate using its CRL Distribution Points.
    Returns a dictionary with status and details.
    """
    result = {"status": "unknown", "checked_uri": None, "reason": None}
    now_utc = datetime.datetime.now(timezone.utc)

    try:
        cdp_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        cdp_value = cdp_ext.value
    except x509.ExtensionNotFound: # No CDP
        logger.info(f"No CRL Distribution Points extension found for cert S/N {hex(cert.serial_number)}")
        result["status"] = "no_cdp"
        result["reason"] = "No CRL Distribution Point extension in certificate."
        return result
    except Exception as e: # Error accessing CDP
        logger.warning(f"Error accessing CRL Distribution Points for cert S/N {hex(cert.serial_number)}: {e}")
        result["status"] = "error"
        result["reason"] = f"Error accessing CDP extension: {e}"
        return result

    http_cdp_uris = []
    for point in cdp_value:
        if point.full_name:
            for general_name in point.full_name:
                if isinstance(general_name, x509.UniformResourceIdentifier):
                    uri = general_name.value
                    parsed_uri = urlparse(uri)
                    if parsed_uri.scheme in ["http", "https"]:
                        http_cdp_uris.append(uri)
                    else: logger.debug(f"Skipping non-HTTP(S) CDP URI: {uri}")

    if not http_cdp_uris: # No HTTP(S) CDP URIs
        logger.warning(f"No HTTP(S) CRL Distribution Points found for cert S/N {hex(cert.serial_number)}")
        result["status"] = "no_http_cdp"
        result["reason"] = "No HTTP(S) URIs found in CRL Distribution Points."
        return result

    logger.info(f"Found {len(http_cdp_uris)} HTTP(S) CDP URIs for cert S/N {hex(cert.serial_number)}: {', '.join(http_cdp_uris)}")

    for uri in http_cdp_uris:
        result["checked_uri"] = uri
        crl_data = download_crl(uri)
        if crl_data is None: # Failed to download CRL
            result["status"] = "unreachable"
            result["reason"] = f"Failed to download CRL from {uri}"
            continue

        crl = parse_crl(crl_data)
        if crl is None: # Failed to parse CRL
            result["status"] = "parse_error"
            result["reason"] = f"Failed to parse CRL downloaded from {uri}"
            continue

        if crl.next_update_utc is None: # No next update time
            logger.warning(f"CRL from {uri} has no next update time. Cannot check expiry.")
        elif crl.next_update_utc < now_utc: # CRL expired
            logger.warning(f"CRL from {uri} has expired (Next Update: {crl.next_update_utc}).")
            result["status"] = "crl_expired"
            result["reason"] = f"CRL expired on {crl.next_update_utc}"
            continue

        revoked_entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)

        if revoked_entry is not None: # Certificate is revoked
            revocation_date = revoked_entry.revocation_date_utc
            logger.warning(f"Certificate S/N {hex(cert.serial_number)} IS REVOKED according to CRL from {uri} (Revoked on: {revocation_date})")
            result["status"] = "revoked"
            result["reason"] = f"Certificate serial number found in CRL (Revoked on: {revocation_date})"
            try:
                reason_ext = revoked_entry.extensions.get_extension_for_oid(CRLEntryExtensionOID.REASON_CODE)
                result["reason"] += f" Reason: {reason_ext.value.reason.name}"
            except x509.ExtensionNotFound: pass
            except Exception as ext_e: logger.warning(f"Could not read CRL entry reason code: {ext_e}")
            return result
        else: # Certificate is not revoked
            logger.info(f"Certificate S/N {hex(cert.serial_number)} is not revoked according to CRL from {uri}")
            result["status"] = "good"
            result["reason"] = "Certificate serial number not found in valid CRL."
            return result

    if result["status"] == "unknown": # Unknown status
        result["reason"] = "Could not determine revocation status from any CDP URI."
    return result

# --- END: CRL Check Functions ---


# --- Core Functions ---

def fetch_leaf_certificate_and_conn_info(domain: str, insecure: bool = False) -> Tuple[Optional[x509.Certificate], Optional[Dict[str, Any]]]:
    """
    Fetch the leaf TLS certificate and basic connection info (TLS version, cipher)
    from a given domain using Python's ssl module.
    Returns (certificate, connection_info) or (None, error_info).
    """
    logger.debug(f"Connecting to {domain}:443 to fetch certificate and connection info...")
    context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    conn_info = {"checked": False, "error": None, "tls_version": None, "supports_tls13": None, "cipher_suite": None, }

    try:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    except AttributeError:
        logger.warning("Could not set minimum TLS version on context (might be older Python/SSL version).")

    sock = None
    ssock = None
    try:
        sock = socket.create_connection((domain, 443), timeout=10)
        ssock = context.wrap_socket(sock, server_hostname=domain)

        conn_info["tls_version"] = ssock.version()
        cipher_details = ssock.cipher()
        if cipher_details: conn_info["cipher_suite"] = cipher_details[0]
        conn_info["supports_tls13"] = conn_info["tls_version"] == "TLSv1.3"
        conn_info["checked"] = True
        logger.info(f"Connection info for {domain}: TLS={conn_info['tls_version']}, Cipher={conn_info['cipher_suite']}")

        der_cert = ssock.getpeercert(binary_form=True)
        if der_cert is None:
            logger.error(f"No certificate received from server {domain}.")
            conn_info["error"] = "No certificate received from server."
            return None, conn_info
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        logger.info(f"Fetched leaf certificate from {domain}")
        return cert, conn_info

    except socket.timeout:
        error_msg = f"Connection to {domain} timed out."
        logger.error(error_msg)
        conn_info["error"] = error_msg
        return None, conn_info
    except ssl.SSLCertVerificationError as e:
        error_msg = f"SSL certificate verification failed for {domain}: {e}."
        if not insecure:
            logger.error(error_msg + " Use -k/--insecure to ignore.")
            conn_info["error"] = error_msg
            return None, conn_info
        else:
            logger.warning(f"Fetching certificate from {domain} insecurely due to verification error: {e}")
            try:
                der_cert = ssock.getpeercert(binary_form=True) if ssock else None
                if der_cert:
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    logger.info(f"Fetched leaf certificate INSECURELY from {domain}")
                    conn_info["error"] = f"Verification failed: {e}"
                    return cert, conn_info
                else:
                    logger.error(f"No certificate received from {domain} even in insecure mode after verification error.")
                    conn_info["error"] = error_msg + " | No cert received in insecure mode."
                    return None, conn_info
            except Exception as inner_e:
                logger.error(f"Failed to fetch certificate insecurely from {domain} after verification error: {inner_e}")
                conn_info["error"] = error_msg + f" | Inner error: {inner_e}"
                return None, conn_info
    except ssl.SSLError as e:
        error_msg = f"An SSL error occurred connecting to {domain}: {e}"
        logger.error(error_msg)
        conn_info["error"] = error_msg
        return None, conn_info
    except ConnectionRefusedError:
        error_msg = f"Connection refused by {domain}:443."
        logger.error(error_msg)
        conn_info["error"] = error_msg
        return None, conn_info
    except socket.gaierror:
        error_msg = f"Could not resolve domain name: {domain}"
        logger.error(error_msg)
        conn_info["error"] = error_msg
        return None, conn_info
    except OSError as e:
        error_msg = f"Network/OS error connecting to {domain}: {e}"
        logger.error(error_msg)
        conn_info["error"] = error_msg
        return None, conn_info
    except Exception as e:
        error_msg = f"An unexpected error occurred during connection/certificate fetch for {domain}: {e}"
        logger.exception(error_msg)
        conn_info["error"] = error_msg
        return None, conn_info
    finally:
        if ssock:
            try: ssock.close()
            except Exception: pass
        if sock:
            try: sock.close()
            except Exception: pass


def fetch_intermediate_certificates(cert: x509.Certificate) -> List[x509.Certificate]:
    """
    Fetch intermediate certificates referenced by the Authority Information Access (AIA) extension.
    """
    intermediates = []
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        ca_issuer_urls = [desc.access_location.value
                          for desc in aia
                          if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS and isinstance(desc.access_location, x509.UniformResourceIdentifier)]

        fetched_urls = set()
        for url in ca_issuer_urls:
            if url in fetched_urls: continue
            fetched_urls.add(url)
            logger.info(f"Fetching intermediate certificate from AIA URL: {url}")
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Python-CertCheck/1.3'})
                with urllib.request.urlopen(req, timeout=10) as response:
                    if response.status == 200:
                        intermediate_der = response.read()
                        content_type = response.info().get_content_type().lower()
                        allowed_types = ['application/pkix-cert', 'application/x-x509-ca-cert', 'application/octet-stream', 'application/pkcs7-mime']
                        if any(allowed in content_type for allowed in allowed_types):
                            try:
                                if b"-----BEGIN CERTIFICATE-----" in intermediate_der:
                                    intermediate_cert = x509.load_pem_x509_certificate(intermediate_der, default_backend())
                                else:
                                    intermediate_cert = x509.load_der_x509_certificate(intermediate_der, default_backend())
                                intermediates.append(intermediate_cert)
                                logger.debug(f"Successfully loaded intermediate from {url}")
                            except ValueError as e: logger.warning(f"Could not parse certificate data from {url}: {e}")
                            except Exception as e: logger.warning(f"Unexpected error parsing certificate from {url}: {e}")
                        else: logger.warning(f"Unexpected content type '{content_type}' for intermediate certificate at {url}")
                    else: logger.warning(f"Failed to fetch intermediate from {url}, status code: {response.status}")
            except urllib.error.URLError as e: logger.warning(f"Failed to fetch intermediate certificate from {url}: {e}")
            except socket.timeout: logger.warning(f"Timeout fetching intermediate certificate from {url}")
            except Exception as e: logger.warning(f"Unexpected error fetching intermediate certificate from {url}: {e}")
    except x509.ExtensionNotFound: logger.info("No AIA extension found in the certificate to fetch intermediates.")
    except Exception as e: logger.warning(f"Error accessing AIA extension: {e}")
    return intermediates


def validate_certificate_chain(domain: str) -> bool:
    """
    Validate the SSL/TLS certificate chain for a given domain using the system's trust store.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                ssock.getpeercert()
        logger.info(f"SSL validation using system trust store OK for {domain}")
        return True
    except ssl.SSLCertVerificationError as e:
        logger.warning(f"SSL validation FAILED for {domain} using system trust store: {e.reason} (Verify code: {e.verify_code}, Message: {e.verify_message})")
        return False
    except ssl.SSLError as e: logger.warning(f"SSL validation FAILED for {domain} due to SSL error: {e}"); return False
    except socket.timeout: logger.warning(f"SSL validation FAILED for {domain}: Connection timed out."); return False
    except socket.gaierror: logger.error(f"SSL validation FAILED for {domain}: Could not resolve domain name."); return False
    except ConnectionRefusedError: logger.error(f"SSL validation FAILED for {domain}: Connection refused."); return False
    except OSError as e: logger.error(f"SSL validation FAILED for {domain}: Network/OS error: {e}"); return False
    except Exception as e: logger.error(f"SSL validation FAILED for {domain}: Unexpected connection error: {e}"); return False


def detect_profile(cert: x509.Certificate) -> str:
    """
    Detect the intended usage profile of a certificate based on its extensions.
    """
    profile = "Unknown / Undetermined"; has_eku = False
    try:
        try:
            ext_key_usage_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            ext_key_usage = ext_key_usage_ext.value; has_eku = True
            usages = list(ext_key_usage)
            if ExtendedKeyUsageOID.SERVER_AUTH in usages:
                profile = "TLS Server"
                other_ekus = [oid for oid in usages if oid != ExtendedKeyUsageOID.SERVER_AUTH]
                if other_ekus: profile += f" (+ {', '.join([oid._name for oid in other_ekus if hasattr(oid, '_name')])})"
            elif ExtendedKeyUsageOID.CLIENT_AUTH in usages: profile = "TLS Client"
            elif ExtendedKeyUsageOID.EMAIL_PROTECTION in usages: profile = "Email Protection (S/MIME)"
            elif ExtendedKeyUsageOID.CODE_SIGNING in usages: profile = "Code Signing"
            elif ExtendedKeyUsageOID.TIME_STAMPING in usages: profile = "Time Stamping"
            elif ExtendedKeyUsageOID.OCSP_SIGNING in usages: profile = "OCSP Signing"
            elif ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE in usages: profile = "Any Extended Key Usage"
            else: profile = f"Custom/Other EKU ({', '.join([oid.dotted_string for oid in usages])})"
            if ext_key_usage_ext.critical: profile += " (Critical)"
        except x509.ExtensionNotFound: logger.debug("No Extended Key Usage extension found, checking Key Usage.")
        try:
            key_usage_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            key_usage = key_usage_ext.value
            if profile == "TLS Server" or profile.startswith("TLS Server ("):
                has_required_ku = (getattr(key_usage, "digital_signature", False) or getattr(key_usage, "key_encipherment", False) or getattr(key_usage, 'key_agreement', False))
                if not has_required_ku: profile += " (Warning: Missing typical KU for TLS)"
            elif profile.startswith("Unknown") or profile == "Custom/Other EKU":
                if getattr(key_usage, "key_cert_sign", False): profile = "CA / Certificate Signing"
                elif getattr(key_usage, "crl_sign", False): profile = "CRL Signing"
                elif getattr(key_usage, "digital_signature", False) and not has_eku: profile = "Digital Signature (Generic)"
                elif getattr(key_usage, "key_encipherment", False) and not has_eku: profile = "Key Encipherment (Generic)"
            if key_usage_ext.critical: profile += " (KU Critical)"
        except x509.ExtensionNotFound:
            if not has_eku: profile = "Legacy / Incomplete (No KU/EKU extensions)"
    except Exception as e: logger.warning(f"Could not detect profile due to error: {e}"); profile = "Error detecting profile"
    return profile


def extract_san(cert: x509.Certificate) -> List[str]:
    """ Extract the Subject Alternative Names (SANs) from a certificate. """
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return [name.value for name in ext.value if isinstance(name, x509.DNSName)]
    except x509.ExtensionNotFound: return []
    except Exception as e: logger.warning(f"Error extracting SANs: {e}"); return []


def get_common_name(subject: x509.Name) -> Optional[str]:
    """Extracts the Common Name (CN) from the certificate subject."""
    try:
        cn_list = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return cn_list[0].value if cn_list else None
    except Exception as e: logger.warning(f"Could not extract Common Name: {e}"); return None


def analyze_certificates(domain: str, mode: str = "full", insecure: bool = False, skip_transparency: bool = False, perform_crl_check: bool = True) -> dict: # CRL default True
    """
    Analyze the TLS certificates for a given domain.
    """
    result = {
        "domain": domain, "analysis_timestamp": datetime.datetime.now(timezone.utc).isoformat(),
        "status": "pending", "error_message": None,
        "connection_health": { "checked": False, "error": None, "tls_version": None, "supports_tls13": None, "cipher_suite": None, },
        "validation": { "system_trust_store": None, "error": None },
        "certificates": [],
        "transparency": { "checked": False, "crtsh_records_found": None, "error": None },
        "crl_check": { "checked": False, "leaf_status": None, "details": None }
    }

    # 1. Fetch Leaf Certificate and Connection Info
    logger.info(f"Fetching leaf certificate and connection info for {domain}...")
    leaf_cert, conn_info = fetch_leaf_certificate_and_conn_info(domain, insecure=insecure)
    if conn_info: result["connection_health"].update(conn_info)
    if leaf_cert is None:
        fetch_error_msg = result["connection_health"].get("error", "Failed to retrieve leaf certificate.")
        logger.error(f"Cannot proceed with certificate analysis for {domain}: {fetch_error_msg}")
        result["status"] = "failed"; result["error_message"] = f"Failed to fetch leaf certificate/connection info: {fetch_error_msg}"
        return result

    # 2. System Trust Store Validation
    logger.info(f"Validating chain against system trust store for {domain}...")
    try:
        result["validation"]["system_trust_store"] = validate_certificate_chain(domain)
        if not result["validation"]["system_trust_store"] and not result["error_message"]:
            result["error_message"] = "System validation failed."
    except Exception as e:
        logger.error(f"Error during system trust validation for {domain}: {e}")
        result["validation"]["error"] = str(e)
        if not result["error_message"]: result["error_message"] = f"System validation error: {e}"

    # 3. Fetch Intermediate Certificates
    certs = [leaf_cert]
    if mode == "full":
        logger.info(f"Fetching intermediate certificates for {domain} via AIA...")
        try:
            intermediates = fetch_intermediate_certificates(leaf_cert)
            certs.extend(intermediates)
            logger.info(f"Found {len(intermediates)} intermediate(s) for {domain} via AIA.")
        except Exception as e: logger.warning(f"Could not fetch or process intermediate certificates for {domain}: {e}")

    # 4. Analyze Each Certificate
    logger.info(f"Analyzing {len(certs)} certificate(s) found for {domain}...")
    all_certs_analyzed = True
    for i, cert in enumerate(certs):
        try:
            key_algo, key_size = get_public_key_details(cert)
            not_before_utc = cert.not_valid_before_utc.replace(tzinfo=timezone.utc) if cert.not_valid_before_utc.tzinfo is None else cert.not_valid_before_utc
            not_after_utc = cert.not_valid_after_utc.replace(tzinfo=timezone.utc) if cert.not_valid_after_utc.tzinfo is None else cert.not_valid_after_utc
            is_ca = False; path_len = None
            try:
                bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
                is_ca = bc.ca; path_len = bc.path_length
            except x509.ExtensionNotFound: is_ca = False
            except Exception as bc_e: logger.warning(f"Could not read BasicConstraints for cert {i}: {bc_e}")
            common_name = get_common_name(cert.subject)
            cert_data = {
                "chain_index": i, "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
                "common_name": common_name, "serial_number": hex(cert.serial_number), "version": str(cert.version),
                "not_before": not_before_utc.isoformat(), "not_after": not_after_utc.isoformat(),
                "days_remaining": calculate_days_remaining(cert), "sha256_fingerprint": get_sha256_fingerprint(cert),
                "signature_algorithm": get_signature_algorithm(cert), "public_key_algorithm": key_algo,
                "public_key_size_bits": key_size, "profile": detect_profile(cert), "san": extract_san(cert),
                "has_scts": has_scts(cert), "is_ca": is_ca, "path_length_constraint": path_len,
            }
            result["certificates"].append(cert_data)
        except Exception as e:
            logger.error(f"Failed to analyze certificate certificate #{i} for {domain}: {e}", exc_info=True)
            all_certs_analyzed = False
            result["certificates"].append({"chain_index": i, "error": f"Failed to parse certificate details: {e}"})

    # 5. CRL Check (Leaf only)
    if perform_crl_check: # Check if CRL should be performed
        logger.info(f"Performing CRL check for leaf certificate of {domain}...")
        result["crl_check"]["checked"] = True
        if leaf_cert:
            try:
                crl_status_details = check_crl(leaf_cert)
                result["crl_check"]["leaf_status"] = crl_status_details.get("status", "error")
                result["crl_check"]["details"] = crl_status_details
                logger.info(f"CRL check result for {domain} leaf: {result['crl_check']['leaf_status']}")
            except Exception as e:
                logger.error(f"Error during CRL check for {domain}: {e}", exc_info=True)
                result["crl_check"]["leaf_status"] = "error"
                result["crl_check"]["details"] = {"status": "error", "reason": f"Unexpected error during check: {e}"}
        else:
            result["crl_check"]["leaf_status"] = "error"
            result["crl_check"]["details"] = {"status": "error", "reason": "Leaf certificate was not available for CRL check."}
    else:
        logger.info(f"Skipping CRL check for {domain} as requested.")
        result["crl_check"]["checked"] = False # Mark as not checked

    # 6. Certificate Transparency Check
    if not skip_transparency:
        logger.info(f"Checking certificate transparency logs for {domain} via crt.sh...")
        result["transparency"]["checked"] = True
        try:
            crtsh_data = query_crtsh(domain)
            if crtsh_data is not None: result["transparency"]["crtsh_records_found"] = len(crtsh_data)
            else:
                result["transparency"]["crtsh_records_found"] = 0
                if not result["transparency"].get("error"): result["transparency"]["error"] = "crt.sh query failed, timed out, or returned no data."
        except Exception as e: logger.error(f"Error querying crt.sh for {domain}: {e}"); result["transparency"]["error"] = str(e)
    else:
        logger.info(f"Skipping certificate transparency check for {domain}.")
        result["transparency"]["checked"] = False

    # Final Status
    if result["status"] != "failed":
        if not result["error_message"] and all_certs_analyzed: result["status"] = "completed"
        else:
            result["status"] = "completed_with_errors"
            error_suffix = "Errors occurred during analysis of some certificates in the chain."
            if result["error_message"] and error_suffix not in result["error_message"]: result["error_message"] += f" | {error_suffix}"
            elif not result["error_message"]: result["error_message"] = error_suffix
    return result


def run_analysis(domains: List[str], output_json: Optional[str] = None, output_csv: Optional[str] = None, mode: str = "full", insecure: bool = False, skip_transparency: bool = False, perform_crl_check: bool = True): # CRL default True
    """
    Run the certificate analysis for a list of domains and output the results.
    """
    results = []; overall_start_time = datetime.datetime.now(timezone.utc)
    logger.info(f"Starting analysis for {len(domains)} domain(s): {', '.join(domains)}")
    logger.info(f"Mode: {mode}, Insecure Fetching: {insecure}, Transparency Check: {not skip_transparency}, CRL Check: {perform_crl_check}")

    for domain in domains:
        logger.info(f"--- Analyzing domain: {domain} ---"); domain_start_time = datetime.datetime.now(timezone.utc)
        try:
            analysis = analyze_certificates(domain, mode, insecure, skip_transparency, perform_crl_check) # Pass flag
            results.append(analysis)
        except Exception as e:
            analysis_ts = datetime.datetime.now(timezone.utc).isoformat(); logger.exception(f"Unexpected critical error during analysis of {domain}: {e}")
            results.append({
                "domain": domain, "analysis_timestamp": analysis_ts, "status": "failed", "error_message": f"Critical analysis error: {e}",
                "connection_health": {"checked": False, "error": "Analysis crashed"}, "validation": {"system_trust_store": None, "error": "Analysis crashed"},
                "certificates": [], "transparency": {"checked": False, "error": "Analysis crashed"},
                "crl_check": {"checked": perform_crl_check, "leaf_status": "error", "details": {"reason": "Analysis crashed"}}, # Reflect if check was attempted
            })
        domain_end_time = datetime.datetime.now(timezone.utc); logger.info(f"--- Finished analyzing {domain} in {(domain_end_time - domain_start_time).total_seconds():.2f}s ---")
    overall_end_time = datetime.datetime.now(timezone.utc); logger.info(f"Completed analysis of {len(domains)} domain(s) in {(overall_end_time - overall_start_time).total_seconds():.2f}s")

    # Output Results
    if output_json:
        out = sys.stdout if output_json == "-" else open(output_json, "w", encoding='utf-8')
        json.dump(results, out, indent=2, ensure_ascii=False)
        if out is not sys.stdout: out.close(); logger.info(f"JSON report written to {output_json}")

    if output_csv:
        out = sys.stdout if output_csv == "-" else open(output_csv, "w", newline='', encoding='utf-8')
        headers = [
            "Domain", "Status", "Error Message", "Analysis Timestamp", "Conn Health Checked", "Conn Health Error", "TLS Version", "Supports TLS 1.3", "Cipher Suite",
            "System Validation", "Validation Error", "CRL Checked", "CRL Leaf Status", "CRL Detail", "Transparency Checked", "CT Records Found", "CT Error",
            "Cert Index", "Cert Error", "Subject", "Issuer", "Common Name", "Serial Number", "Version", "Not Before", "Not After", "Days Remaining",
            "SHA256 Fingerprint", "Signature Algorithm", "Public Key Algorithm", "Public Key Size", "Profile", "SANs", "Has SCTs", "Is CA", "Path Length Constraint"
        ]
        writer = csv.writer(out); writer.writerow(headers)
        for result in results:
            domain = result.get("domain", "N/A"); status = result.get("status", "failed"); error_msg = result.get("error_message", "Unknown error"); analysis_ts = result.get("analysis_timestamp", "N/A")
            conn = result.get("connection_health", {}); conn_checked = conn.get("checked", False); conn_error = conn.get("error", ""); tls_version = conn.get("tls_version", "N/A"); tls13 = conn.get("supports_tls13", "N/A"); cipher = conn.get("cipher_suite", "N/A")
            val = result.get("validation", {}); sys_val = val.get("system_trust_store")
            if val_status is True: val_text = '\033[92m✔️ Valid (System Trust)\033[0m'
            elif val_status is False: val_text = f'\033[91m❌ Invalid (System Trust){" (" + val.get("error", "") + ")" if val.get("error") else ""}\033[0m'
            elif val.get('error'): val_text = f"\033[91m❌ Error ({val['error']})\033[0m"
            else: val_text = "\033[93m❓ Unknown/Skipped\033[0m"
            print(f"  Validation  : {val_text}")

            certs_list = result.get('certificates', []); leaf_cert_data = certs_list[0] if certs_list and 'error' not in certs_list[0] else None
            if leaf_cert_data:
                print("\n  \033[1mLeaf Certificate Summary:\033[0m"); print(f"    Common Name: \033[96m{leaf_cert_data.get('common_name', 'N/A')}\033[0m")
                days_left_leaf = leaf_cert_data.get('days_remaining', None); expiry_text_leaf = leaf_cert_data.get('not_after', 'N/A')
                if days_left_leaf is not None: expiry_color_leaf = '\033[91m' if days_left_leaf < 30 else ('\033[93m' if days_left_leaf < 90 else '\033[92m'); expiry_text_leaf += f" ({expiry_color_leaf}{days_left_leaf} days remaining\033[0m)"
                else: expiry_text_leaf += " (\033[93mExpiry N/A\033[0m)"
                print(f"    Expires    : {expiry_text_leaf}")
                sans_leaf = leaf_cert_data.get('san', []); max_sans_display = 5; sans_display = ', '.join(sans_leaf[:max_sans_display]);
                if len(sans_leaf) > max_sans_display: sans_display += f", ... ({len(sans_leaf) - max_sans_display} more)"
                print(f"    SANs       : {sans_display if sans_leaf else 'None'}"); print(f"    Issuer     : {leaf_cert_data.get('issuer', 'N/A')}")

            conn = result.get('connection_health', {}); print("\n  \033[1mConnection Health:\033[0m")
            if not conn.get('checked'): print("    Status      : \033[93mNot Checked / Failed\033[0m");
            else:
                print(f"    TLS Version : {conn.get('tls_version', 'N/A')}")
                tls13_support = conn.get('supports_tls13'); tls13_text = '\033[92mYes\033[0m' if tls13_support is True else ('\033[91mNo\033[0m' if tls13_support is False else '\033[93mN/A\033[0m'); print(f"    TLS 1.3     : {tls13_text}")
                print(f"    Cipher Suite: {conn.get('cipher_suite', 'N/A')}")
            if conn.get('error'): print(f"    Error       : \033[91m{conn['error']}\033[0m")

            crl_check_data = result.get('crl_check', {}); print("\n  \033[1mCRL Check (Leaf):\033[0m")
            if not crl_check_data.get('checked'): print("    Status      : \033[93mSkipped\033[0m")
            else:
                crl_status = crl_check_data.get('leaf_status', 'error'); crl_details = crl_check_data.get('details', {}); crl_reason = crl_details.get('reason', 'No details available.') if isinstance(crl_details, dict) else 'Invalid details format.'; crl_uri = crl_details.get('checked_uri') if isinstance(crl_details, dict) else None
                status_map = {"good": "\033[92m✔️ Good\033[0m", "revoked": "\033[91m❌ REVOKED\033[0m", "crl_expired": "\033[93m⚠️ CRL Expired\033[0m", "unreachable": "\033[93m⚠️ Unreachable\033[0m", "parse_error": "\033[91m❌ Parse Error\033[0m", "no_cdp": "\033[94mℹ️ No CDP\033[0m", "no_http_cdp": "\033[94mℹ️ No HTTP CDP\033[0m", "error": "\033[91m❌ Error\033[0m"}
                status_text = status_map.get(crl_status, "\033[93m❓ Unknown\033[0m")
                print(f"    Status      : {status_text}"); print(f"    Detail      : {crl_reason}");
                if crl_uri: print(f"    Checked URI : {crl_uri}")

            cert_count_color = '\033[92m' if certs_list else '\033[91m'; print(f"\n  \033[1mCertificate Chain Details:\033[0m ({cert_count_color}{len(certs_list)} found\033[0m)")
            if not certs_list and status != 'failed': print("    \033[93mNo certificates were processed successfully.\033[0m")
            for i, cert in enumerate(certs_list):
                is_leaf = cert.get("chain_index", -1) == 0; title_suffix = " (Error Analyzing)" if cert.get('error') else (" (Leaf)" if is_leaf else (" (CA/Intermediate)" if cert.get("is_ca") else " (Intermediate)")); cert_title = f"Certificate {i+1}{title_suffix}"
                print(f"\n    \033[1;4m{cert_title}:\033[0m");
                if cert.get('error'): print(f"      \033[91mError: {cert['error']}\033[0m"); continue
                days_left = cert.get('days_remaining', None); expiry_text = cert.get('not_after', 'N/A')
                if days_left is not None: expiry_color = '\033[91m' if days_left < 30 else ('\033[93m' if days_left < 90 else '\033[92m'); expiry_text += f" ({expiry_color}{days_left} days remaining\033[0m)"
                else: expiry_text += " (\033[93mExpiry N/A\033[0m)"
                key_size = cert.get('public_key_size_bits'); key_algo = cert.get('public_key_algorithm', 'N/A'); key_weak = (key_algo == 'RSA' and key_size < 2048) or ('ECDSA' in key_algo and key_size < 256) or (key_algo == 'DSA' and key_size < 2048) if key_size else False; key_size_color = '\033[91m' if key_weak else '\033[92m'; key_text = f"{key_algo} ({key_size_color}{key_size} bits\033[0m)" if key_size else key_algo;
                if key_weak: key_text += " \033[91m(Potentially Weak)\033[0m"
                sig_algo = cert.get('signature_algorithm', 'N/A'); sig_weak = 'sha1' in sig_algo.lower() or 'md5' in sig_algo.lower(); sig_color = '\033[91m' if sig_weak else '\033[92m'; sig_text = f"{sig_color}{sig_algo}\033[0m";
                if sig_weak: sig_text += " \033[91m(Weak Hash)\033[0m"
                sct_support = cert.get('has_scts'); sct_text = '\033[92m✔️ Yes\033[0m' if sct_support is True else ('\033[93m❌ No\033[0m' if sct_support is False else '\033[93mN/A\033[0m')
                print(f"      Subject    : {cert.get('subject', 'N/A')}"); print(f"      Issuer     : {cert.get('issuer', 'N/A')}"); print(f"      Serial     : {cert.get('serial_number', 'N/A')}"); print(f"      Version    : {cert.get('version', 'N/A')}"); print(f"      Valid From : {cert.get('not_before', 'N/A')}"); print(f"      Valid Until: {expiry_text}"); print(f"      Key        : {key_text}"); print(f"      Signature  : {sig_text}"); print(f"      SHA256 FP  : {cert.get('sha256_fingerprint', 'N/A')}"); print(f"      Profile    : {cert.get('profile', 'N/A')}"); print(f"      SANs       : {', '.join(cert.get('san', [])) or 'None'}"); print(f"      Is CA      : {'Yes' if cert.get('is_ca') else 'No'}");
                if cert.get('is_ca'): print(f"      Path Len   : {'None' if cert.get('path_length_constraint') is None else cert.get('path_length_constraint')}"); print(f"      Embedded SCTs: {sct_text}")

            trans = result.get('transparency', {}); print("\n  \033[1mCertificate Transparency (crt.sh):\033[0m")
            if not trans.get('checked'): print("    Status      : \033[93mSkipped\033[0m")
            elif trans.get('error'): print(f"    Status      : \033[91mError ({trans['error']})\033[0m")
            else:
                found = trans.get('crtsh_records_found', 0); status_color = '\033[92m' if found is not None else '\033[91m'; print(f"    Status      : {status_color}Checked\033[0m"); found_color = '\033[92m' if found > 0 else ('\033[93m' if found == 0 else '\033[91m'); print(f"    Records Found: {found_color}{found if found is not None else 'Error'}\033[0m")


# --- Web Server ---

HTML_TEMPLATE = """
<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>
<style>
    /* Default Light Mode */
    :root {
        --bg-color: #f8f9fa; --text-color: #212529; --card-bg: #ffffff;
        --card-border: rgba(0, 0, 0, 0.175); --table-header-bg: #e9ecef;
        --table-border: #dee2e6; --input-bg: #ffffff; --input-border: #ced4da;
        --input-text: #495057; --muted-text: #6c757d; --link-color: #0d6efd;
        --shadow-color: rgba(0, 0, 0, 0.1); --success-text: #198754;
        --warning-text: #ffc107; --danger-text: #dc3545; --secondary-text: #6c757d;
        --info-text: #0dcaf0; /* For info like 'No CDP' */
        --info-badge-bg: #0dcaf0; --secondary-badge-bg: #6c757d;
        --success-badge-bg: #198754; --warning-badge-bg: #ffc107;
        --danger-badge-bg: #dc3545; --info-badge-text: black; /* Text color for info badge */
        --alert-danger-bg: #f8d7da; --alert-danger-border: #f5c6cb; --alert-danger-text: #842029;
        --alert-warning-bg: #fff3cd; --alert-warning-border: #ffecb5; --alert-warning-text: #664d03;
        --form-check-input-bg: #ffffff; --form-check-input-border: rgba(0, 0, 0, 0.25);
        --form-check-input-checked-bg: #0d6efd; --form-check-input-checked-border: #0d6efd;
        --form-check-label-color: var(--text-color);
    }
    body { padding-top: 20px; background-color: var(--bg-color); color: var(--text-color); transition: background-color 0.3s, color 0.3s; }
    .container { max-width: 1140px; } /* Limit width */
    .card { background-color: var(--card-bg); border: 1px solid var(--card-border); box-shadow: 0 0.125rem 0.25rem var(--shadow-color); margin-bottom: 1.5rem; }
    .card-header { background-color: transparent; border-bottom: 1px solid var(--card-border); padding: 0.75rem 1.25rem; display: flex; justify-content: space-between; align-items: center; }
    .card-header strong { font-size: 1.2em; }
    .card-body { padding: 1.25rem; }
    .table { border-color: var(--table-border); margin-bottom: 1rem; }
    .table th { width: 150px; background-color: var(--table-header-bg); white-space: nowrap; color: var(--text-color); padding: 0.5rem; vertical-align: top; }
    .table td { color: var(--text-color); padding: 0.5rem; vertical-align: top; word-break: break-word; } /* Allow td content to wrap */
    .table-sm > :not(caption) > * > * { padding: 0.25rem 0.25rem; }
    .table-bordered { border: 1px solid var(--table-border); }
    .table-bordered th, .table-bordered td { border: 1px solid var(--table-border); }
    .badge { font-size: 0.9em; padding: 0.4em 0.6em;}
    .bg-success { background-color: var(--success-badge-bg) !important; color: white; }
    .bg-warning { background-color: var(--warning-badge-bg) !important; color: black; }
    .bg-danger { background-color: var(--danger-badge-bg) !important; color: white; }
    .bg-secondary { background-color: var(--secondary-badge-bg) !important; color: white; }
    .bg-info { background-color: var(--info-badge-bg) !important; color: var(--info-badge-text); } /* Uses variable */
    .fingerprint { font-family: monospace; font-size: 0.85em; word-break: break-all; }
    .text-danger { color: var(--danger-text) !important; }
    .text-warning { color: var(--warning-text) !important; }
    .text-success { color: var(--success-text) !important; }
    .text-muted { color: var(--muted-text) !important; }
    .text-secondary { color: var(--secondary-text) !important; }
    .text-info { color: var(--info-text) !important; } /* For info text */
    .section-title { border-bottom: 1px solid var(--table-border); padding-bottom: 5px; margin-bottom: 15px; margin-top: 1.5rem; font-weight: bold; }
    .card-body > div + div { margin-top: 1.5rem; }
    .cert-error { background-color: #f8d7da; border-color: #f5c6cb; color: #721c24; padding: 0.5rem; margin-top: 0.5rem; border-radius: .25rem;}
    .weak-crypto { font-weight: bold; color: var(--danger-text) !important; }
    .form-control { background-color: var(--input-bg); border: 1px solid var(--input-border); color: var(--input-text); }
    .form-control:focus { background-color: var(--input-bg); color: var(--input-text); border-color: #86b7fe; box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25); }
    .form-label { color: var(--text-color); }
    .form-check-label { color: var(--form-check-label-color); }
    .form-check-input { background-color: var(--form-check-input-bg); border: 1px solid var(--form-check-input-border); }
    .form-check-input:checked { background-color: var(--form-check-input-checked-bg); border-color: var(--form-check-input-checked-border); }
    .form-check-input:focus { border-color: #86b7fe; box-shadow: 0 0 0 0.25rem rgba(13,110,253,.25); }
    .alert { border-radius: .25rem; padding: 1rem; margin-bottom: 1rem;}
    .alert-danger { background-color: var(--alert-danger-bg); border: 1px solid var(--alert-danger-border); color: var(--alert-danger-text); }
    .alert-warning { background-color: var(--alert-warning-bg); border: 1px solid var(--alert-warning-border); color: var(--alert-warning-text); }
    footer small { color: var(--muted-text); }
    a { color: var(--link-color); }

    @media (prefers-color-scheme: dark) {
        :root {
            --bg-color: #181a1b; --text-color: #f4f4f4; --card-bg: #23272b;
            --card-border: #33363a;
            --table-header-bg: #292b2d;
            --table-border: #44474a; --input-bg: #23272b; --input-border: #666a6e;
            --input-text: #f4f4f4; --muted-text: #b0b3b8; --link-color: #7dbcff;
            --shadow-color: rgba(0, 0, 0, 0.4); --success-text: #5cf2b2;
            --warning-text: #ffe066; --danger-text: #ff7b72; --secondary-text: #b0b3b8;
            --info-text: #7dbcff;
            --info-badge-bg: #206bc4; --secondary-badge-bg: #5a6268;
            --success-badge-bg: #2ecc71; --warning-badge-bg: #ffe066;
            --danger-badge-bg: #ff4c51; --info-badge-text: #23272b;
            --alert-danger-bg: #3b2326; --alert-danger-border: #a0414b; --alert-danger-text: #ffb3b8;
            --alert-warning-bg: #665c03; --alert-warning-border: #c2a700; --alert-warning-text: #fffbe3;
            --form-check-input-bg: #292b2d; --form-check-input-border: #666a6e;
            --form-check-input-checked-bg: #0d6efd; --form-check-input-checked-border: #0d6efd;
            --form-check-label-color: var(--text-color);
        }
        .form-control, .form-select {
            background-color: var(--input-bg) !important;
            color: var(--input-text) !important;
            border-color: var(--input-border) !important;
        }
        .form-control::placeholder { color: #b0b3b8; }
        .form-select { background-color: var(--input-bg); border-color: var(--input-border); color: var(--input-text); }
        .form-check-input:focus { border-color: #86b7fe; box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25); }
        .form-check-input[type=checkbox] { border-radius: .25em; }
        .bg-warning { color: #222 !important; } /* Keep warning text black */
        .cert-error { background-color: #5e2129; border-color: #a0414b; color: #ffb3b8; }
        .table th, .table td {
            background-color: var(--card-bg) !important;
            color: var(--text-color) !important;
            border-color: var(--table-border) !important;
        }
        body { background-color: var(--bg-color) !important; color: var(--text-color) !important; }
        .card, .shadow-sm { background-color: var(--card-bg) !important; color: var(--text-color) !important; }
    }
</style>
<title>TLS Analysis</title>
</head>
<body>
<div class='container'>
<h1 class='mb-4 text-center'>🔒 TLS Certificate & Connection Analyzer</h1>
<form method='post' class='mb-5 p-4 border rounded shadow-sm' style='background-color: var(--card-bg);'>
<div class='mb-3'>
<label for='domains' class='form-label'>Domains to analyze (space or comma separated):</label>
<input type='text' class='form-control form-control-lg' id='domains' name='domains' placeholder='e.g. example.com test.org google.com' required>
</div>
<div class='row'>
    <div class='col-md-4 mb-3'>
        <div class='form-check'>
        <input class='form-check-input' type='checkbox' id='insecure' name='insecure' value='true' {% if insecure_checked %}checked{% endif %}>
        <label class='form-check-label' for='insecure'> Ignore SSL errors</label>
        </div>
    </div>
    <div class='col-md-4 mb-3'>
        <div class='form-check'>
        <input class='form-check-input' type='checkbox' id='no_transparency' name='no_transparency' value='true' {% if no_transparency_checked %}checked{% endif %}>
        <label class='form-check-label' for='no_transparency'> Skip Transparency Check</label>
        </div>
    </div>
    {# --- Updated CRL Checkbox --- #}
    <div class='col-md-4 mb-3'>
        <div class='form-check'>
        <input class='form-check-input' type='checkbox' id='no_crl_check' name='no_crl_check' value='true' {% if no_crl_check_checked %}checked{% endif %}>
        <label class='form-check-label' for='no_crl_check'> Disable CRL Check</label>
        </div>
    </div>
</div>
<button type='submit' class='btn btn-primary w-100 btn-lg'>Analyze</button>
</form>

{% if results %}
{% for result in results %}
<div class='card mb-4 shadow-sm'>
<div class='card-header'>
<strong>{{ result.domain }}</strong>
{% set status = result.status | default('failed') %}
{% if status == 'completed' %}<span class='badge bg-success'>COMPLETED</span>
{% elif status == 'completed_with_errors' %}<span class='badge bg-warning'>COMPLETED WITH ERRORS</span>
{% else %}<span class='badge bg-danger'>FAILED</span>{% endif %}
</div>
<div class='card-body'>
    {% if result.error_message %}<div class='alert alert-danger'><strong>Status:</strong> {{ result.error_message }}</div>{% endif %}
    <p class='text-muted'><small>Analysis Time: {{ result.analysis_timestamp | default('N/A') }}</small></p>

    {# Validation Section #}
    <div> <h5 class='section-title'>Validation</h5>
        {% set val = result.validation | default({}) %} {% set val_status = val.system_trust_store %}
        {% if val_status is sameas true %}<span class='badge bg-success'>✔️ Valid (System Trust)</span>
        {% elif val_status is sameas false %}<span class='badge bg-danger'>❌ Invalid (System Trust)</span> {% if val.error %}<small class='text-muted ps-2'>({{ val.error }})</small>{% endif %}
        {% elif val.error %}<span class='badge bg-danger'>❌ Error</span> <small class='text-muted ps-2'>({{ val.error }})</small>
        {% else %}<span class='badge bg-secondary'>N/A / Pending</span> {% endif %}
    </div>

    {# Leaf Certificate Summary Section #}
    {% set certs_list = result.certificates | default([]) %}
    {% set leaf_cert = certs_list[0] if certs_list and 'error' not in certs_list[0] else none %}
    {% if leaf_cert %}
    <div> <h5 class='section-title'>Leaf Certificate Summary</h5>
        <table class='table table-sm table-bordered'>
             <tr><th>Common Name</th><td>{{ leaf_cert.common_name | default('N/A') }}</td></tr>
             <tr><th>Expires</th><td>
                 {% set days_leaf = leaf_cert.days_remaining %}
                 {{ (leaf_cert.not_after | replace("T", " ") | replace("Z", "") | replace("+00:00", ""))[:19] | default('N/A') }}
                 {% if days_leaf is not none %}<span class='{% if days_leaf < 30 %}text-danger{% elif days_leaf < 90 %}text-warning{% else %}text-success{% endif %} fw-bold'> ({{ days_leaf }} days)</span>
                 {% else %}<span class='text-secondary'>(Expiry N/A)</span> {% endif %}
             </td></tr>
             <tr><th>SANs</th><td>{{ leaf_cert.san | join(", ") | default('None') }}</td></tr>
             <tr><th>Issuer</th><td>{{ leaf_cert.issuer | default('N/A') }}</td></tr>
        </table>
    </div>
    {% endif %}

    {# Connection Health Section #}
    <div> <h5 class='section-title'>Connection Health</h5>
        {% set conn = result.connection_health | default({}) %}
        {% if not conn.checked %}<span class='badge bg-warning'>Not Checked / Failed</span> {% if conn.error %}<small class='text-muted ps-2'>({{ conn.error }})</small>{% endif %}
        {% else %}
        <table class='table table-sm table-bordered'>
            <tr><th>TLS Version</th><td>{{ conn.tls_version | default('N/A') }}</td></tr>
            <tr><th>TLS 1.3 Support</th><td>
                {% set tls13_s = conn.supports_tls13 %}
                {% if tls13_s is sameas true %}<span class='text-success'>✔️ Yes</span>
                {% elif tls13_s is sameas false %}<span class='text-danger'>❌ No</span>
                {% else %}<span class='text-secondary'>N/A</span>{% endif %}
            </td></tr>
            <tr><th>Cipher Suite</th><td>{{ conn.cipher_suite | default('N/A') }}</td></tr>
        </table>
        {% if conn.error %}<div class='alert alert-danger mt-2'><small>Connection Error: {{ conn.error }}</small></div>{% endif %}
        {% endif %}
    </div>

    {# CRL Check Section #}
    <div><h5 class='section-title'>CRL Check (Leaf Certificate)</h5>
        {% set crl_check_data = result.crl_check | default({}) %}
        {% if not crl_check_data.checked %}
             <span class='badge bg-secondary'>Skipped</span>
        {% else %}
            {% set crl_status = crl_check_data.leaf_status | default('error') %}
            {% set crl_details = crl_check_data.details | default({}) %}
            {% set crl_reason = crl_details.reason if crl_details is mapping else 'No details' %}
            {% set crl_uri = crl_details.checked_uri if crl_details is mapping else None %}

            {% if crl_status == "good" %} <span class='badge bg-success'>✔️ Good</span>
            {% elif crl_status == "revoked" %} <span class='badge bg-danger'>❌ REVOKED</span>
            {% elif crl_status == "crl_expired" %} <span class='badge bg-warning'>⚠️ CRL Expired</span>
            {% elif crl_status == "unreachable" %} <span class='badge bg-warning'>⚠️ Unreachable</span>
            {% elif crl_status == "parse_error" %} <span class='badge bg-danger'>❌ Parse Error</span>
            {% elif crl_status == "no_cdp" %} <span class='badge bg-info'>ℹ️ No CDP</span>
            {% elif crl_status == "no_http_cdp" %} <span class='badge bg-info'>ℹ️ No HTTP CDP</span>
            {% elif crl_status == "error" %} <span class='badge bg-danger'>❌ Error</span>
            {% else %} <span class='badge bg-secondary'>❓ Unknown</span>
            {% endif %}
            <p class='text-muted mt-1'><small>
                {{ crl_reason }}
                {% if crl_uri %} <br>Checked URI: {{ crl_uri }} {% endif %}
            </small></p>
        {% endif %}
    </div>

    {# Certificate Chain Details Section #}
     <div> <h5 class='section-title'>Certificate Chain Details ({{ certs_list | length }})</h5>
        {% if not certs_list and result.status != 'failed' %}<div class='alert alert-warning'>No certificates were processed successfully.</div>
        {% elif not certs_list and result.status == 'failed' %}<div class='alert alert-danger'>Certificate fetching or analysis failed.</div>
        {% endif %}
        {% for cert in certs_list %}
            <h6 class="mt-3">Certificate #{{ loop.index }}
                {% if cert.error %} <span class='text-danger'>(Error Analyzing)</span>
                {% elif cert.chain_index == 0 %} (Leaf)
                {% elif cert.is_ca %} (CA/Intermediate)
                {% else %} (Intermediate) {% endif %}
             </h6>
            {% if cert.error %}<div class='cert-error'><strong>Error:</strong> {{ cert.error }}</div>
            {% else %}
            <table class='table table-sm table-bordered mb-3'>
                <tr><th>Subject</th><td>{{ cert.subject | default('N/A') }}</td></tr>
                <tr><th>Issuer</th><td>{{ cert.issuer | default('N/A') }}</td></tr>
                <tr><th>Common Name</th><td>{{ cert.common_name | default('N/A') }}</td></tr>
                <tr><th>Serial</th><td>{{ cert.serial_number | default('N/A') }}</td></tr>
                <tr><th>Version</th><td>{{ cert.version | default('N/A') }}</td></tr>
                <tr><th>Validity</th><td>
                    {{ (cert.not_before | replace("T", " ") | replace("Z", "") | replace("+00:00", ""))[:19] | default('N/A') }} →
                    {{ (cert.not_after | replace("T", " ") | replace("Z", "") | replace("+00:00", ""))[:19] | default('N/A') }} <br>
                    {% set days = cert.days_remaining %}
                    {% if days is not none %}<span class='{% if days < 30 %}text-danger{% elif days < 90 %}text-warning{% else %}text-success{% endif %} fw-bold'> ({{ days }} days remaining)</span>
                    {% else %}<span class='text-secondary'>(Expiry N/A)</span> {% endif %}
                </td></tr>
                <tr><th>Key</th><td>
                    {% set k_algo = cert.public_key_algorithm | default('N/A') %} {% set k_size = cert.public_key_size_bits %} {{ k_algo }}
                    {% if k_size %}
                        {% set weak_key = (k_algo == 'RSA' and k_size < 2048) or ('ECDSA' in k_algo and k_size < 256) or (k_algo == 'DSA' and k_size < 2048) %}
                        (<span class='{% if weak_key %}weak-crypto{% endif %}'>{{ k_size }} bits</span>){% if weak_key %}<span class='weak-crypto ps-1'>(Weak)</span>{% endif %}
                    {% endif %}
                </td></tr>
                <tr><th>Signature Algo</th><td>
                     {% set sig_algo = cert.signature_algorithm | default('N/A') %} {% set weak_hash = "sha1" in sig_algo.lower() or "md5" in sig_algo.lower() %}
                     <span class='{% if weak_hash %}weak-crypto{% endif %}'>{{ sig_algo }}</span>{% if weak_hash %}<span class='weak-crypto ps-1'>(Weak)</span>{% endif %}
                </td></tr>
                 <tr><th>SHA256 FP</th><td class='fingerprint'>{{ cert.sha256_fingerprint | default('N/A') }}</td></tr>
                <tr><th>Profile</th><td>{{ cert.profile | default('N/A') }}</td></tr>
                <tr><th>SANs</th><td>{{ cert.san | join(", ") | default('None') }}</td></tr>
                <tr><th>Is CA</th><td> {% if cert.is_ca is sameas true %}Yes{% elif cert.is_ca is sameas false %}No{% else %}N/A{% endif %} {% if cert.is_ca %} (PathLen: {{ cert.path_length_constraint if cert.path_length_constraint is not none else 'None' }}) {% endif %} </td></tr>
                <tr><th>Embedded SCTs</th><td>
                    {% set sct_s = cert.has_scts %}
                    {% if sct_s is sameas true %}<span class='text-success'>✔️ Yes</span>
                    {% elif sct_s is sameas false %}<span class='text-warning'>❌ No</span>
                    {% else %}<span class='text-secondary'>N/A</span>{% endif %}
                </td></tr>
            </table>
            {% endif %}
        {% endfor %}
    </div>

    {# Certificate Transparency Section #}
    <div> <h5 class='section-title'>Certificate Transparency (crt.sh)</h5>
         {% set trans = result.transparency | default({}) %}
         {% if not trans.checked %}<span class='badge bg-secondary'>Skipped</span>
         {% elif trans.error %}<span class='badge bg-danger'>Error</span> <small class='text-muted ps-2'>({{ trans.error }})</small>
         {% else %}
              {% set found = trans.crtsh_records_found %}
              <span class='badge {% if found is not none %}bg-success{% else %}bg-danger{% endif %}'>Checked</span>
              {% if found is not none %}
                 <span class='ps-2'>Records found:</span>
                 <span class='badge {% if found > 0 %}bg-info{% else %}bg-secondary{% endif %}'>{{ found }}</span>
              {% endif %}
         {% endif %}
    </div>

</div> {# End Card Body #}
</div> {# End Card #}
{% endfor %}
{% endif %}
<footer class='text-center text-muted mt-5 mb-3'> <small>TLS Analyzer Tool v1.7 (CRL Default ON)</small> </footer>
</div>
<script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js'></script>
</body>
</html>
"""


def run_server(args):
    """
    Run the Flask web server for interactive TLS analysis.
    """
    app = Flask(__name__)
    app.config['SCRIPT_ARGS'] = args

    @app.route('/', methods=['GET', 'POST'])
    def index():
        script_args = current_app.config['SCRIPT_ARGS']
        results = None
        # Get defaults from startup args
        insecure_checked = script_args.insecure
        no_transparency_checked = script_args.no_transparency
        no_crl_check_checked = script_args.no_crl_check # Default for disabling CRL

        if request.method == 'POST':
            raw_domains = request.form.get('domains', '')
            domains = [d.strip() for d in raw_domains.replace(',', ' ').split() if d.strip()]

            # Read current form submission
            insecure_flag = request.form.get('insecure') == 'true'
            no_transparency_flag = request.form.get('no_transparency') == 'true'
            no_crl_check_flag = request.form.get('no_crl_check') == 'true' # Read disable flag

            # Update checkbox state for re-rendering based on submission
            insecure_checked = insecure_flag
            no_transparency_checked = no_transparency_flag
            no_crl_check_checked = no_crl_check_flag # State for re-render

            # Determine effective settings (combine startup args and form submission)
            effective_insecure = script_args.insecure or insecure_flag
            effective_skip_transparency = script_args.no_transparency or no_transparency_flag
            effective_disable_crl = script_args.no_crl_check or no_crl_check_flag # Effective disable flag

            analysis_results = []
            # Determine if CRL check should be performed (perform unless effectively disabled)
            perform_crl = not effective_disable_crl
            logger.info(f"Web request: Analyzing {domains} (insecure={effective_insecure}, skip_transparency={effective_skip_transparency}, check_crl={perform_crl})") # Log if performing
            for domain in domains:
                try:
                    analysis = analyze_certificates(
                        domain,
                        mode=script_args.mode,
                        insecure=effective_insecure,
                        skip_transparency=effective_skip_transparency,
                        perform_crl_check=perform_crl # Pass whether to perform
                    )
                    analysis_results.append(analysis)
                except Exception as e:
                    analysis_ts = datetime.datetime.now(timezone.utc).isoformat()
                    logger.exception(f"Web request: Critical error analyzing {domain}: {e}")
                    analysis_results.append({
                        "domain": domain, "analysis_timestamp": analysis_ts, "status": "failed", "error_message": f"Server error during analysis: {e}",
                         "connection_health": {"checked": False, "error": "Analysis crashed"}, "validation": {"system_trust_store": None, "error": "Analysis crashed"},
                        "certificates": [], "transparency": {"checked": False, "error": "Analysis crashed"},
                        "crl_check": {"checked": perform_crl, "leaf_status": "error", "details": {"reason": "Analysis crashed"}}, # Reflect if check was attempted
                    })
            results = analysis_results

        accept_header = request.accept_mimetypes.best_match(['application/json', 'text/html'])
        if accept_header == 'application/json' and results is not None:
            response = jsonify(results); response.mimetype = 'application/json; charset=utf-8'; return response
        else:
            # Pass all checkbox states to template
            return render_template_string(HTML_TEMPLATE, results=results,
                                          insecure_checked=insecure_checked,
                                          no_transparency_checked=no_transparency_checked,
                                          no_crl_check_checked=no_crl_check_checked) # Pass disable state

    logger.info(f"Starting Flask server on http://0.0.0.0:{args.port}")
    try: app.run(host='0.0.0.0', port=args.port, debug=False)
    except Exception as e: logger.error(f"Failed to start Flask server: {e}")


def get_flask_app():
    """Function to return the app instance, needed for WSGI servers like waitress."""
    parser = argparse.ArgumentParser(add_help=False)
    # --- Update CRL argument for WSGI context if needed ---
    parser.add_argument("-m", "--mode", choices=["simple", "full"], default="full")
    parser.add_argument("-k", "--insecure", action="store_true")
    parser.add_argument("--no-transparency", action="store_true")
    parser.add_argument("--no-crl-check", action="store_true") # Use disable flag
    parser.add_argument("-p", "--port", type=int, default=8000)
    parser.add_argument("-l", "--loglevel", default="WARN")

    server_args, _ = parser.parse_known_args()

    app_loglevel = getattr(logging, server_args.loglevel.upper(), logging.WARNING)
    app_log_format = '%(asctime)s [%(levelname)-8s] %(name)s (Flask): %(message)s'
    try:
        import coloredlogs; coloredlogs.install(level=app_loglevel, logger=logger, fmt=app_log_format)
    except ImportError:
        logging.basicConfig(level=app_loglevel, format=app_log_format)
        logger.warning("coloredlogs library not found for Flask app logging.")

    app = Flask(__name__)
    app.config['SCRIPT_ARGS'] = server_args

    @app.route('/', methods=['GET', 'POST'])
    def index(): # Duplicating route definition is necessary for WSGI entry point
        script_args = current_app.config['SCRIPT_ARGS']
        results = None
        insecure_checked = script_args.insecure
        no_transparency_checked = script_args.no_transparency
        no_crl_check_checked = script_args.no_crl_check # Default disable state

        if request.method == 'POST':
            raw_domains = request.form.get('domains', ''); domains = [d.strip() for d in raw_domains.replace(',', ' ').split() if d.strip()]
            insecure_flag = request.form.get('insecure') == 'true'
            no_transparency_flag = request.form.get('no_transparency') == 'true'
            no_crl_check_flag = request.form.get('no_crl_check') == 'true'

            insecure_checked = insecure_flag; no_transparency_checked = no_transparency_flag; no_crl_check_checked = no_crl_check_flag

            effective_insecure = script_args.insecure or insecure_flag
            effective_skip_transparency = script_args.no_transparency or no_transparency_flag
            effective_disable_crl = script_args.no_crl_check or no_crl_check_flag
            perform_crl = not effective_disable_crl

            analysis_results = []
            logger.info(f"Flask App: Analyzing {domains} (insecure={effective_insecure}, skip_transparency={effective_skip_transparency}, check_crl={perform_crl})")
            for domain in domains:
                try:
                    analysis = analyze_certificates( domain, mode=script_args.mode, insecure=effective_insecure, skip_transparency=effective_skip_transparency, perform_crl_check=perform_crl )
                    analysis_results.append(analysis)
                except Exception as e:
                    analysis_ts = datetime.datetime.now(timezone.utc).isoformat(); logger.exception(f"Flask App: Critical error analyzing {domain}: {e}")
                    analysis_results.append({
                        "domain": domain, "analysis_timestamp": analysis_ts, "status": "failed", "error_message": f"Server error during analysis: {e}",
                        "connection_health": {"checked": False, "error": "Analysis crashed"}, "validation": {"system_trust_store": None, "error": "Analysis crashed"},
                        "certificates": [], "transparency": {"checked": False, "error": "Analysis crashed"},
                        "crl_check": {"checked": perform_crl, "leaf_status": "error", "details": {"reason": "Analysis crashed"}},
                    })
            results = analysis_results

        accept_header = request.accept_mimetypes.best_match(['application/json', 'text/html'])
        if accept_header == 'application/json' and results is not None:
            response = jsonify(results); response.mimetype = 'application/json; charset=utf-8'; return response
        else:
            from flask import current_app # Needed within route
            return render_template_string(HTML_TEMPLATE, results=results,
                                          insecure_checked=insecure_checked,
                                          no_transparency_checked=no_transparency_checked,
                                          no_crl_check_checked=no_crl_check_checked) # Pass disable state

    from flask import current_app # Needed for route definition scope
    return app


def main():
    """ Entry point for the script. """
    parser = argparse.ArgumentParser(
        description="Analyze TLS certificates with profile detection, crypto details, connection health, CRL checks (default ON), and transparency checks.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    cli_group = parser.add_argument_group('CLI Mode Options')
    cli_group.add_argument("domains", nargs="*", help="List of domains to check (required unless running in server mode).")
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument("-j", "--json", help="Output JSON report to specified file ('-' for stdout).")
    output_group.add_argument("-c", "--csv", help="Output CSV report to specified file ('-' for stdout).")
    analysis_group = parser.add_argument_group('Analysis Options')
    analysis_group.add_argument("-m", "--mode", choices=["simple", "full"], default="full", help="Choose analysis mode:\n simple: Leaf certificate only.\n full: Fetch leaf and attempt to fetch intermediates via AIA (default).")
    analysis_group.add_argument("-k", "--insecure", action="store_true", help="Allow fetching certificates without SSL verification.\nWARNING: This bypasses security checks.")
    analysis_group.add_argument("--no-transparency", action="store_true", help="Skip the crt.sh certificate transparency check.")
    # --- Updated CRL argument ---
    analysis_group.add_argument("--no-crl-check", action="store_true", help="Disable CRL check for the leaf certificate (experimental).")

    server_group = parser.add_argument_group('Server Mode Options')
    server_group.add_argument("-s", "--server", action="store_true", help="Run as HTTP server with web interface.")
    server_group.add_argument("-p", "--port", type=int, default=8000, help="Specify server port (default: 8000). Used only with --server.")
    general_group = parser.add_argument_group('General Options')
    general_group.add_argument("-l", "--loglevel", default="WARN", choices=["DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"], help="Set log level (default: WARN).")

    args = parser.parse_args()

    # Setup Logging (omitted for brevity - same as before)
    loglevel = getattr(logging, args.loglevel.upper(), logging.WARNING)
    log_format = '%(asctime)s [%(levelname)-8s] %(name)s: %(message)s' if loglevel > logging.DEBUG else '%(asctime)s [%(levelname)-8s] %(name)s (%(filename)s:%(lineno)d): %(message)s'
    logger.propagate = False
    if not logger.hasHandlers():
        handler = logging.StreamHandler(sys.stderr)
        formatter = None; can_color = False
        if 'coloredlogs' in sys.modules and hasattr(sys.stderr, 'isatty') and sys.stderr.isatty():
            try: coloredlogs.install(level=loglevel, logger=logger, fmt=log_format, stream=sys.stderr); can_color = True
            except Exception as log_ex: logger.warning(f"Could not install coloredlogs: {log_ex}"); formatter = logging.Formatter(log_format)
        else: formatter = logging.Formatter(log_format)
        if not can_color and formatter: handler.setFormatter(formatter); logger.addHandler(handler)
    logger.setLevel(loglevel)
    if 'coloredlogs' not in sys.modules: logger.info("coloredlogs library not found, using standard logging.")

    if args.server:
        if args.domains: logger.warning("Domain arguments are ignored when running in server mode (--server).")
        if args.json or args.csv: logger.warning("JSON/CSV output flags are ignored when running in server mode (--server).")
        logger.info("Starting web server...")
        run_server(args)
    elif not args.domains:
        parser.error("the following arguments are required: domains (or use --server)")
    else:
        # Run CLI analysis - determine if CRL check should be performed
        perform_crl = not args.no_crl_check # Perform unless disable flag is set
        run_analysis(
            args.domains,
            output_json=args.json,
            output_csv=args.csv,
            mode=args.mode,
            insecure=args.insecure,
            skip_transparency=args.no_transparency,
            perform_crl_check=perform_crl # Pass the final decision
        )

if __name__ == "__main__":
    main()
