# Core certificate analysis logic

import logging
import datetime
from datetime import timezone
import socket
import ssl
import sys
import csv
from typing import List, Optional, Dict, Any, Tuple
from check_tls.utils.cert_utils import *
from check_tls.utils.crl_utils import *
from check_tls.utils.crtsh_utils import *
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID
import urllib.request


def fetch_leaf_certificate_and_conn_info(domain: str, insecure: bool = False) -> Tuple[Optional[x509.Certificate], Optional[Dict[str, Any]]]:
    logger = logging.getLogger("certcheck")
    logger.debug(f"Connecting to {domain}:443 to fetch certificate and connection info...")
    context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    conn_info = {"checked": False, "error": None, "tls_version": None, "supports_tls13": None, "cipher_suite": None}
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
        if cipher_details:
            conn_info["cipher_suite"] = cipher_details[0]
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
            try:
                ssock.close()
            except Exception:
                pass
        if sock:
            try:
                sock.close()
            except Exception:
                pass

def fetch_intermediate_certificates(cert: x509.Certificate) -> List[x509.Certificate]:
    logger = logging.getLogger("certcheck")
    intermediates = []
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        ca_issuer_urls = [desc.access_location.value for desc in aia if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS and isinstance(desc.access_location, x509.UniformResourceIdentifier)]
        fetched_urls = set()
        for url in ca_issuer_urls:
            if url in fetched_urls:
                continue
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
                            except ValueError as e:
                                logger.warning(f"Could not parse certificate data from {url}: {e}")
                            except Exception as e:
                                logger.warning(f"Unexpected error parsing certificate from {url}: {e}")
                        else:
                            logger.warning(f"Unexpected content type '{content_type}' for intermediate certificate at {url}")
                    else:
                        logger.warning(f"Failed to fetch intermediate from {url}, status code: {response.status}")
            except urllib.error.URLError as e:
                logger.warning(f"Failed to fetch intermediate certificate from {url}: {e}")
            except socket.timeout:
                logger.warning(f"Timeout fetching intermediate certificate from {url}")
            except Exception as e:
                logger.warning(f"Unexpected error fetching intermediate certificate from {url}: {e}")
    except x509.ExtensionNotFound:
        logger.info("No AIA extension found in the certificate to fetch intermediates.")
    except Exception as e:
        logger.warning(f"Error accessing AIA extension: {e}")
    return intermediates

def validate_certificate_chain(domain: str) -> bool:
    logger = logging.getLogger("certcheck")
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
    except ssl.SSLError as e:
        logger.warning(f"SSL validation FAILED for {domain} due to SSL error: {e}")
        return False
    except socket.timeout:
        logger.warning(f"SSL validation FAILED for {domain}: Connection timed out.")
        return False
    except socket.gaierror:
        logger.error(f"SSL validation FAILED for {domain}: Could not resolve domain name.")
        return False
    except ConnectionRefusedError:
        logger.error(f"SSL validation FAILED for {domain}: Connection refused.")
        return False
    except OSError as e:
        logger.error(f"SSL validation FAILED for {domain}: Network/OS error: {e}")
        return False
    except Exception as e:
        logger.error(f"SSL validation FAILED for {domain}: Unexpected connection error: {e}")
        return False

def detect_profile(cert: x509.Certificate) -> str:
    logger = logging.getLogger("certcheck")
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
                if getattr(key_usage, "digital_signature", False) and not has_eku: profile = "Digital Signature (Generic)"
                elif getattr(key_usage, "key_encipherment", False) and not has_eku: profile = "Key Encipherment (Generic)"
            if key_usage_ext.critical: profile += " (KU Critical)"
        except x509.ExtensionNotFound:
            if not has_eku: profile = "Legacy / Incomplete (No KU/EKU extensions)"
    except Exception as e:
        logger.warning(f"Could not detect profile due to error: {e}"); profile = "Error detecting profile"
    return profile

def analyze_certificates(domain: str, mode: str = "full", insecure: bool = False, skip_transparency: bool = False, perform_crl_check: bool = True) -> dict:
    logger = logging.getLogger("certcheck")
    result = {
        "domain": domain, "analysis_timestamp": datetime.datetime.now(timezone.utc).isoformat(),
        "status": "pending", "error_message": None,
        "connection_health": { "checked": False, "error": None, "tls_version": None, "supports_tls13": None, "cipher_suite": None, },
        "validation": { "system_trust_store": None, "error": None },
        "certificates": [],
        "transparency": { "checked": False, "crtsh_records_found": None, "error": None },
        "crl_check": { "checked": False, "leaf_status": None, "details": None }
    }
    logger.info(f"Fetching leaf certificate and connection info for {domain}...")
    leaf_cert, conn_info = fetch_leaf_certificate_and_conn_info(domain, insecure=insecure)
    if conn_info: result["connection_health"].update(conn_info)
    if leaf_cert is None:
        fetch_error_msg = result["connection_health"].get("error", "Failed to retrieve leaf certificate.")
        logger.error(f"Cannot proceed with certificate analysis for {domain}: {fetch_error_msg}")
        result["status"] = "failed"; result["error_message"] = f"Failed to fetch leaf certificate/connection info: {fetch_error_msg}"
        return result
    logger.info(f"Validating chain against system trust store for {domain}...")
    try:
        result["validation"]["system_trust_store"] = validate_certificate_chain(domain)
        if not result["validation"]["system_trust_store"] and not result["error_message"]:
            result["error_message"] = "System validation failed."
    except Exception as e:
        logger.error(f"Error during system trust validation for {domain}: {e}")
        result["validation"]["error"] = str(e)
        if not result["error_message"]: result["error_message"] = f"System validation error: {e}"
    certs = [leaf_cert]
    if mode == "full":
        logger.info(f"Fetching intermediate certificates for {domain} via AIA...")
        try:
            intermediates = fetch_intermediate_certificates(leaf_cert)
            certs.extend(intermediates)
            logger.info(f"Found {len(intermediates)} intermediate(s) for {domain} via AIA.")
        except Exception as e:
            logger.warning(f"Could not fetch or process intermediate certificates for {domain}: {e}")
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
            except x509.ExtensionNotFound:
                is_ca = False
            except Exception as bc_e:
                logger.warning(f"Could not read BasicConstraints for cert {i}: {bc_e}")
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
    if perform_crl_check:
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
        result["crl_check"]["checked"] = False
    if not skip_transparency:
        logger.info(f"Checking certificate transparency logs for {domain} via crt.sh...")
        result["transparency"]["checked"] = True
        try:
            crtsh_data = query_crtsh(domain)
            if crtsh_data is not None:
                result["transparency"]["crtsh_records_found"] = len(crtsh_data)
            else:
                result["transparency"]["crtsh_records_found"] = 0
                if not result["transparency"].get("error"):
                    result["transparency"]["error"] = "crt.sh query failed, timed out, or returned no data."
        except Exception as e:
            logger.error(f"Error querying crt.sh for {domain}: {e}")
            result["transparency"]["error"] = str(e)
    else:
        logger.info(f"Skipping certificate transparency check for {domain}.")
        result["transparency"]["checked"] = False
    if result["status"] != "failed":
        if not result["error_message"] and all_certs_analyzed:
            result["status"] = "completed"
        else:
            result["status"] = "completed_with_errors"
            error_suffix = "Errors occurred during analysis of some certificates in the chain."
            if result["error_message"] and error_suffix not in result["error_message"]:
                result["error_message"] += f" | {error_suffix}"
            elif not result["error_message"]:
                result["error_message"] = error_suffix
    return result

def get_log_level(level_str: str):
    """
    Convert a string log level (e.g., 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
    to the corresponding logging module constant. Defaults to logging.WARNING.
    """
    return getattr(logging, level_str.upper(), logging.WARNING)

def run_analysis(domains: List[str], output_json: Optional[str] = None, output_csv: Optional[str] = None, mode: str = "full", insecure: bool = False, skip_transparency: bool = False, perform_crl_check: bool = True):
    logger = logging.getLogger("certcheck")
    results = []
    overall_start_time = datetime.datetime.now(timezone.utc)
    logger.info(f"Starting analysis for {len(domains)} domain(s): {', '.join(domains)}")
    logger.info(f"Mode: {mode}, Insecure Fetching: {insecure}, Transparency Check: {not skip_transparency}, CRL Check: {perform_crl_check}")
    for domain in domains:
        logger.info(f"--- Analyzing domain: {domain} ---")
        domain_start_time = datetime.datetime.now(timezone.utc)
        try:
            analysis = analyze_certificates(domain, mode, insecure, skip_transparency, perform_crl_check)
            results.append(analysis)
        except Exception as e:
            analysis_ts = datetime.datetime.now(timezone.utc).isoformat()
            logger.exception(f"Unexpected critical error during analysis of {domain}: {e}")
            results.append({
                "domain": domain, "analysis_timestamp": analysis_ts, "status": "failed", "error_message": f"Critical analysis error: {e}",
                "connection_health": {"checked": False, "error": "Analysis crashed"}, "validation": {"system_trust_store": None, "error": "Analysis crashed"},
                "certificates": [], "transparency": {"checked": False, "error": "Analysis crashed"},
                "crl_check": {"checked": perform_crl_check, "leaf_status": "error", "details": {"reason": "Analysis crashed"}},
            })
        domain_end_time = datetime.datetime.now(timezone.utc)
        logger.info(f"--- Finished analyzing {domain} in {(domain_end_time - domain_start_time).total_seconds():.2f}s ---")
    overall_end_time = datetime.datetime.now(timezone.utc)
    logger.info(f"Completed analysis of {len(domains)} domain(s) in {(overall_end_time - overall_start_time).total_seconds():.2f}s")
    if output_json:
        out = sys.stdout if output_json == "-" else open(output_json, "w", encoding='utf-8')
        import json
        json.dump(results, out, indent=2, ensure_ascii=False)
        if out is not sys.stdout:
            out.close()
            logger.info(f"JSON report written to {output_json}")
    if output_csv:
        out = sys.stdout if output_csv == "-" else open(output_csv, "w", newline='', encoding='utf-8')
        writer = csv.writer(out)
        headers = [
            "Domain", "Status", "Error Message", "Analysis Timestamp", "Conn Health Checked", "Conn Health Error", "TLS Version", "Supports TLS 1.3", "Cipher Suite",
            "System Validation", "Validation Error", "CRL Checked", "CRL Leaf Status", "CRL Detail", "Transparency Checked", "CT Records Found", "CT Error",
            "Cert Index", "Cert Error", "Subject", "Issuer", "Common Name", "Serial Number", "Version", "Not Before", "Not After", "Days Remaining",
            "SHA256 Fingerprint", "Signature Algorithm", "Public Key Algorithm", "Public Key Size", "Profile", "SANs", "Has SCTs", "Is CA", "Path Length Constraint"
        ]
        writer.writerow(headers)
        for result in results:
            domain = result.get("domain", "N/A")
            status = result.get("status", "failed")
            error_msg = result.get("error_message", "Unknown error")
            analysis_ts = result.get("analysis_timestamp", "N/A")
            conn = result.get("connection_health", {})
            conn_checked = conn.get("checked", False)
            conn_error = conn.get("error", "")
            tls_version = conn.get("tls_version", "N/A")
            tls13 = conn.get("supports_tls13", "N/A")
            cipher = conn.get("cipher_suite", "N/A")
            val = result.get("validation", {})
            sys_val = val.get("system_trust_store")
            val_error = val.get("error", "")
            crl = result.get("crl_check", {})
            crl_checked = crl.get("checked", False)
            crl_leaf_status = crl.get("leaf_status", "")
            crl_detail = crl.get("details", "")
            transparency = result.get("transparency", {})
            ct_checked = transparency.get("checked", False)
            ct_records = transparency.get("crtsh_records_found", "")
            ct_error = transparency.get("error", "")
            certs_list = result.get("certificates", [])
            if not certs_list:
                writer.writerow([
                    domain, status, error_msg, analysis_ts, conn_checked, conn_error, tls_version, tls13, cipher,
                    sys_val, val_error, crl_checked, crl_leaf_status, crl_detail, ct_checked, ct_records, ct_error,
                    "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""
                ])
            else:
                for cert in certs_list:
                    writer.writerow([
                        domain, status, error_msg, analysis_ts, conn_checked, conn_error, tls_version, tls13, cipher,
                        sys_val, val_error, crl_checked, crl_leaf_status, crl_detail, ct_checked, ct_records, ct_error,
                        cert.get("chain_index", ""), cert.get("error", ""), cert.get("subject", ""), cert.get("issuer", ""), cert.get("common_name", ""), cert.get("serial_number", ""), cert.get("version", ""), cert.get("not_before", ""), cert.get("not_after", ""), cert.get("days_remaining", ""), cert.get("sha256_fingerprint", ""), cert.get("signature_algorithm", ""), cert.get("public_key_algorithm", ""), cert.get("public_key_size_bits", ""), cert.get("profile", ""), ", ".join(cert.get("san", [])), cert.get("has_scts", ""), cert.get("is_ca", ""), cert.get("path_length_constraint", "")
                    ])
        if out is not sys.stdout:
            out.close()
            logger.info(f"CSV report written to {output_csv}")
