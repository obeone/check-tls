# Core certificate analysis logic

import logging
import datetime
from datetime import timezone
import socket
import ssl
import sys
import csv
from typing import List, Optional, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor
from check_tls.utils.cert_utils import *
from check_tls.utils.crl_utils import *
from check_tls.utils.crtsh_utils import query_crtsh, query_crtsh_multi
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID
import urllib.request
import json


def fetch_leaf_certificate_and_conn_info(domain: str, port: int = 443, insecure: bool = False) -> Tuple[Optional[x509.Certificate], Optional[Dict[str, Any]]]:
    """
    Fetch the leaf TLS certificate and connection information from a domain's server.

    Parameters:
        domain (str): The domain name to connect to.
        port (int): The port number to connect to.
        insecure (bool): If True, ignore SSL certificate verification errors.

    Returns:
        Tuple[Optional[x509.Certificate], Optional[Dict[str, Any]]]:
            - The leaf x509 certificate if successfully fetched, else None.
            - A dictionary with connection info including TLS version, cipher suite, and error details if any.
    """
    logger = logging.getLogger("certcheck")
    logger.debug(f"Connecting to {domain}:{port} to fetch certificate and connection info...")

    # Create SSL context, optionally ignoring verification errors if insecure is True
    context = ssl._create_unverified_context() if insecure else ssl.create_default_context()

    # Initialize connection info dictionary with default values
    conn_info = {
        "checked": False,
        "error": None,
        "tls_version": None,
        "supports_tls13": None,
        "cipher_suite": None,
    }

    try:
        # Set minimum TLS version to 1.2 if supported by the SSL module
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    except AttributeError:
        logger.warning("Could not set minimum TLS version on context (might be older Python/SSL version).")

    sock = None
    ssock = None

    try:
        # Establish TCP connection to domain on specified port with timeout
        sock = socket.create_connection((domain, port), timeout=10)
        # Wrap socket with SSL context for TLS handshake
        ssock = context.wrap_socket(sock, server_hostname=domain)

        # Extract TLS version and cipher suite details
        conn_info["tls_version"] = ssock.version()
        cipher_details = ssock.cipher()
        if cipher_details:
            conn_info["cipher_suite"] = cipher_details[0]
        conn_info["supports_tls13"] = conn_info["tls_version"] == "TLSv1.3"
        conn_info["checked"] = True

        logger.info(f"Connection info for {domain}: TLS={conn_info['tls_version']}, Cipher={conn_info['cipher_suite']}")

        # Get the peer certificate in DER format
        der_cert = ssock.getpeercert(binary_form=True)
        if der_cert is None:
            logger.error(f"No certificate received from server {domain}.")
            conn_info["error"] = "No certificate received from server."
            return None, conn_info

        # Load the DER certificate into an x509 object
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        logger.info(f"Fetched leaf certificate from {domain}")
        return cert, conn_info

    except socket.timeout:
        error_msg = f"Connection to {domain}:{port} timed out."
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
        error_msg = f"Connection refused by {domain}:{port}."
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
    """
    Fetch intermediate certificates referenced by the Authority Information Access (AIA) extension of a certificate.

    Parameters:
        cert (x509.Certificate): The leaf or intermediate certificate to fetch intermediates for.

    Returns:
        List[x509.Certificate]: A list of intermediate certificates fetched from AIA URLs.
    """
    import urllib.error  # Import here to fix type error and ensure availability

    logger = logging.getLogger("certcheck")
    intermediates = []

    try:
        # Get the AIA extension value which contains URLs to intermediate certs
        aia_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        # aia_ext.value is the AuthorityInformationAccess object, which is iterable
        # and contains AccessDescription objects.

        # Extract CA Issuer URLs from AIA extension
        ca_issuer_urls = []
        # Iterate over AccessDescription objects in aia_ext.value
        # aia_ext.value is an instance of AuthorityInformationAccess, which is iterable
        # The .value of an AuthorityInformationAccess extension is an iterable of AccessDescription objects
        # Ensure aia_ext.value is treated as an iterable of AccessDescription
        # The type of aia_ext.value should be x509.AuthorityInformationAccess
        # which is a sequence of x509.AccessDescription.
        if isinstance(aia_ext.value, x509.AuthorityInformationAccess):
            for desc in aia_ext.value:
                if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS and isinstance(desc.access_location, x509.UniformResourceIdentifier):
                    ca_issuer_urls.append(desc.access_location.value)
        else:
            logger.warning(f"AIA extension value is not of expected type AuthorityInformationAccess for {cert.subject}")

        fetched_urls = set()

        for url in ca_issuer_urls:
            if url in fetched_urls:
                continue
            fetched_urls.add(url)
            logger.info(f"Fetching intermediate certificate from AIA URL: {url}")

            try:
                # Corrected urllib.request usage
                req = urllib.request.Request(url, headers={'User-Agent': 'Python-CertCheck/1.3'})
                with urllib.request.urlopen(req, timeout=10) as response:
                    if response.status == 200:
                        intermediate_der = response.read()
                        content_type = response.info().get_content_type().lower()
                        allowed_types = [
                            'application/pkix-cert',
                            'application/x-x509-ca-cert',
                            'application/octet-stream',
                            'application/pkcs7-mime'
                        ]
                        if any(allowed in content_type for allowed in allowed_types):
                            try:
                                # Detect PEM or DER format and load accordingly
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

def validate_certificate_chain(domain: str, port: int = 443) -> bool:
    """
    Validate the certificate chain of a domain against the system's trust store.

    Parameters:
        domain (str): The domain to validate.
        port (int): The port to connect to for validation.

    Returns:
        bool: True if validation is successful, False otherwise.
    """
    logger = logging.getLogger("certcheck")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                ssock.getpeercert() # This implicitly validates the chain
        logger.info(f"SSL validation using system trust store OK for {domain}:{port}")
        return True
    except ssl.SSLCertVerificationError as e:
        logger.warning(f"SSL validation FAILED for {domain}:{port} using system trust store: {e.reason} (Verify code: {e.verify_code}, Message: {e.verify_message})")
        return False
    except ssl.SSLError as e:
        logger.warning(f"SSL validation FAILED for {domain}:{port} due to SSL error: {e}")
        return False
    except socket.timeout:
        logger.warning(f"SSL validation FAILED for {domain}:{port}: Connection timed out.")
        return False
    except socket.gaierror:
        logger.error(f"SSL validation FAILED for {domain}:{port}: Could not resolve domain name.")
        return False
    except ConnectionRefusedError:
        logger.error(f"SSL validation FAILED for {domain}:{port}: Connection refused.")
        return False
    except OSError as e:
        logger.error(f"SSL validation FAILED for {domain}:{port}: Network/OS error: {e}")
        return False
    except Exception as e:
        logger.error(f"SSL validation FAILED for {domain}:{port}: Unexpected connection error: {e}")
        return False

def detect_profile(cert: x509.Certificate) -> str:
    """
    Detect the certificate profile based on Extended Key Usage (EKU) and Key Usage (KU) extensions.

    Parameters:
        cert (x509.Certificate): The certificate to analyze.

    Returns:
        str: A string describing the detected profile of the certificate.
    """
    logger = logging.getLogger("certcheck")
    profile = "Unknown / Undetermined"
    has_eku = False

    try:
        # Attempt to get Extended Key Usage extension
        ext_key_usage_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        # ext_key_usage_ext.value is the ExtendedKeyUsage object, which is iterable
        # and contains OID objects.
        has_eku = True

        # ext_key_usage_ext.value is an instance of ExtendedKeyUsage, which is iterable
        # The .value of an ExtendedKeyUsage extension is an iterable of OID objects
        # Ensure ext_key_usage_ext.value is treated as an iterable of OIDs
        # The type of ext_key_usage_ext.value should be x509.ExtendedKeyUsage
        # which is a sequence of x509.ObjectIdentifier.
        if isinstance(ext_key_usage_ext.value, x509.ExtendedKeyUsage):
            usages = list(ext_key_usage_ext.value)
        else:
            logger.warning(f"ExtendedKeyUsage extension value is not of expected type ExtendedKeyUsage for {cert.subject}")
            usages = [] # Default to empty list if type is unexpected

        if ExtendedKeyUsageOID.SERVER_AUTH in usages:
            profile = "TLS Server"
            other_ekus = [oid for oid in usages if oid != ExtendedKeyUsageOID.SERVER_AUTH]
            if other_ekus:
                profile += f" (+ {', '.join([oid._name for oid in other_ekus if hasattr(oid, '_name')])})"
        elif ExtendedKeyUsageOID.CLIENT_AUTH in usages:
            profile = "TLS Client"
        elif ExtendedKeyUsageOID.EMAIL_PROTECTION in usages:
            profile = "Email Protection (S/MIME)"
        elif ExtendedKeyUsageOID.CODE_SIGNING in usages:
            profile = "Code Signing"
        elif ExtendedKeyUsageOID.TIME_STAMPING in usages:
            profile = "Time Stamping"
        elif ExtendedKeyUsageOID.OCSP_SIGNING in usages:
            profile = "OCSP Signing"
        elif ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE in usages:
            profile = "Any Extended Key Usage"
        else:
            profile = f"Custom/Other EKU ({', '.join([oid.dotted_string for oid in usages])})" # Ensure oid has dotted_string

        if ext_key_usage_ext.critical:
            profile += " (Critical)"

    except x509.ExtensionNotFound:
        logger.debug("No Extended Key Usage extension found, checking Key Usage.")

    try:
        # Attempt to get Key Usage extension
        key_usage_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        key_usage = key_usage_ext.value

        # Access attributes safely with getattr
        if profile == "TLS Server" or profile.startswith("TLS Server ("):
            has_required_ku = (
                getattr(key_usage, "digital_signature", False)
                or getattr(key_usage, "key_encipherment", False)
                or getattr(key_usage, "key_agreement", False)
            )
            if not has_required_ku:
                profile += " (Warning: Missing typical KU for TLS)"
        elif profile.startswith("Unknown") or profile == "Custom/Other EKU":
            if getattr(key_usage, "digital_signature", False) and not has_eku:
                profile = "Digital Signature (Generic)"
            elif getattr(key_usage, "key_encipherment", False) and not has_eku:
                profile = "Key Encipherment (Generic)"

        if key_usage_ext.critical:
            profile += " (KU Critical)"

    except x509.ExtensionNotFound:
        if not has_eku:
            profile = "Legacy / Incomplete (No KU/EKU extensions)"

    except Exception as e:
        logger.warning(f"Could not detect profile due to error: {e}")
        profile = "Error detecting profile"

    return profile

def analyze_certificates(domain: str, port: int = 443, mode: str = "full", insecure: bool = False, skip_transparency: bool = False, perform_crl_check: bool = True, perform_ocsp_check: bool = True) -> dict:
    """
    Analyze the certificates of a domain, including leaf and intermediate certificates,
    perform validation, CRL, OCSP checks, and certificate transparency checks.

    Parameters:
        domain (str): The domain to analyze.
        port (int): The port to connect to.
        mode (str): Analysis mode, "full" to fetch intermediates, otherwise leaf only.
        insecure (bool): Whether to ignore SSL verification errors when fetching certificates.
        skip_transparency (bool): Whether to skip Certificate Transparency log checks.
        perform_crl_check (bool): Whether to perform Certificate Revocation List (CRL) checks.
        perform_ocsp_check (bool): Whether to perform Online Certificate Status Protocol (OCSP) checks.

    Returns:
        dict: A dictionary containing analysis results, including connection info,
              validation status, certificate details, transparency info, CRL and OCSP check results.
    """
    logger = logging.getLogger("certcheck")
    result = {
        "domain": f"{domain}:{port}", # Include port in the domain identifier for clarity
        "analysis_timestamp": datetime.datetime.now(timezone.utc).isoformat(),
        "status": "pending",
        "error_message": None,
        "connection_health": {
            "checked": False,
            "error": None,
            "tls_version": None,
            "supports_tls13": None,
            "cipher_suite": None,
        },
        "validation": {
            "system_trust_store": None,
            "error": None,
        },
        "certificates": [],
        "transparency": {
            "checked": False,
            "crtsh_records_found": None,
            "error": None,
            "details": None,
            "errors": None,
        },
        "crl_check": {
            "checked": False,
            "leaf_status": None,
            "details": None,
        },
        "ocsp_check": { # OCSP check results
            "checked": False,
            "status": None,
            "details": None,
        },
    }

    logger.info(f"Fetching leaf certificate and connection info for {domain}:{port}...")
    leaf_cert, conn_info = fetch_leaf_certificate_and_conn_info(domain, port=port, insecure=insecure)
    if conn_info:
        result["connection_health"].update(conn_info)

    if leaf_cert is None:
        fetch_error_msg = result["connection_health"].get("error", "Failed to retrieve leaf certificate.")
        logger.error(f"Cannot proceed with certificate analysis for {domain}:{port}: {fetch_error_msg}")
        result["status"] = "failed"
        result["error_message"] = f"Failed to fetch leaf certificate/connection info for {domain}:{port}: {fetch_error_msg}"
        return result

    logger.info(f"Validating chain against system trust store for {domain}:{port}...")
    try:
        result["validation"]["system_trust_store"] = validate_certificate_chain(domain, port=port)
        if not result["validation"]["system_trust_store"] and not result["error_message"]:
            result["error_message"] = f"System validation failed for {domain}:{port}."
    except Exception as e:
        logger.error(f"Error during system trust validation for {domain}:{port}: {e}")
        result["validation"]["error"] = str(e)
        if not result["error_message"]:
            result["error_message"] = f"System validation error for {domain}:{port}: {e}"

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

            # Normalize datetime to UTC if naive
            not_before_utc = cert.not_valid_before_utc.replace(tzinfo=timezone.utc) if cert.not_valid_before_utc.tzinfo is None else cert.not_valid_before_utc
            not_after_utc = cert.not_valid_after_utc.replace(tzinfo=timezone.utc) if cert.not_valid_after_utc.tzinfo is None else cert.not_valid_after_utc

            is_ca = False
            path_len = None
            try:
                bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                # bc_ext.value is the BasicConstraints object
                # bc_ext.value is an instance of BasicConstraints
                # bc_ext.value is an instance of x509.BasicConstraints
                # Ensure bc_ext.value is treated as a BasicConstraints object
                # The type of bc_ext.value should be x509.BasicConstraints.
                basic_constraints_obj = bc_ext.value
                if isinstance(basic_constraints_obj, x509.BasicConstraints):
                    is_ca = basic_constraints_obj.ca
                    path_len = basic_constraints_obj.path_length
                else:
                    logger.warning(f"BasicConstraints extension value is not of expected type BasicConstraints for {cert.subject}")
                    # is_ca and path_len remain their default (False, None)
            except x509.ExtensionNotFound:
                is_ca = False # Default if extension not found
            except Exception as bc_e:
                logger.warning(f"Could not read BasicConstraints for cert {i}: {bc_e}")

            common_name = get_common_name(cert.subject)

            cert_data = {
                "chain_index": i,
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "common_name": common_name,
                "serial_number": hex(cert.serial_number),
                "version": str(cert.version),
                "not_before": not_before_utc.isoformat(),
                "not_after": not_after_utc.isoformat(),
                "days_remaining": calculate_days_remaining(cert),
                "sha256_fingerprint": get_sha256_fingerprint(cert),
                "signature_algorithm": get_signature_algorithm(cert),
                "public_key_algorithm": key_algo,
                "public_key_size_bits": key_size,
                "profile": detect_profile(cert),
                "san": extract_san(cert),
                "has_scts": has_scts(cert),
                "is_ca": is_ca,
                "path_length_constraint": path_len,
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

    # OCSP Check (Online Certificate Status Protocol)
    if perform_ocsp_check:
        logger.info(f"Performing OCSP check for leaf certificate of {domain}...")
        result["ocsp_check"]["checked"] = True
        if leaf_cert:
            try:
                # Deduce issuer_cert as the next certificate in the chain if available,
                # otherwise, assume leaf_cert is self-signed or issuer is not directly available for OCSP.
                # For OCSP, the immediate issuer of the leaf_cert is needed.
                # If only leaf_cert is present in `certs`, it might be self-signed or the chain is incomplete.
                # A more robust solution might involve fetching the issuer based on AIA if not provided.
                issuer_cert = certs[1] if len(certs) > 1 else leaf_cert # Fallback to leaf_cert if no clear issuer in chain
                
                # Dynamically import check_ocsp to avoid circular dependencies if ocsp_utils imports from tls_checker
                from check_tls.utils.ocsp_utils import check_ocsp
                ocsp_details = check_ocsp(leaf_cert, issuer_cert)
                result["ocsp_check"]["status"] = ocsp_details.get("status")
                result["ocsp_check"]["details"] = ocsp_details
                logger.info(f"OCSP check result for {domain} leaf: {result['ocsp_check']['status']}")
            except ImportError as e:
                logger.error(f"Could not import check_ocsp for {domain}. OCSP check skipped. Error : {e}")
                result["ocsp_check"]["status"] = "error"
                result["ocsp_check"]["details"] = {"error": "Failed to import OCSP utility."}
            except Exception as e:
                logger.error(f"Error during OCSP check for {domain}: {e}", exc_info=True)
                result["ocsp_check"]["status"] = "error"
                result["ocsp_check"]["details"] = {"error": str(e)}
        else:
            result["ocsp_check"]["status"] = "error"
            result["ocsp_check"]["details"] = {"error": "Leaf certificate was not available for OCSP check."}
    else:
        logger.info(f"Skipping OCSP check for {domain} as requested.")
        result["ocsp_check"]["checked"] = False

    # Certificate Transparency check (domain + parent domains)
    if not skip_transparency:
        ct_results = query_crtsh_multi(domain)
        transparency_summary = {
            'checked': True,
            'details': {},
            'total_records': 0,
            'errors': {},
            'crtsh_report_links': {},
        }
        for d, res in ct_results.items():
            if res is None:
                transparency_summary['errors'][d] = 'error or timeout'
                transparency_summary['details'][d] = None
                transparency_summary['crtsh_report_links'][d] = f"https://crt.sh/?q={d}"
            else:
                transparency_summary['details'][d] = res
                transparency_summary['total_records'] += len(res)
                transparency_summary['crtsh_report_links'][d] = f"https://crt.sh/?q={d}"
        transparency_summary['crtsh_records_found'] = transparency_summary['total_records']
        result['transparency'] = transparency_summary
    else:
        result['transparency'] = {'checked': False}

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

def run_analysis(domains_input: List[str], output_json: Optional[str] = None, output_csv: Optional[str] = None, mode: str = "full", insecure: bool = False, skip_transparency: bool = False, perform_crl_check: bool = True, perform_ocsp_check: bool = True):
    """
    Run TLS analysis for a list of domains (which can include ports) and output results.

    Parameters:
        domains_input (List[str]): List of domain strings. Each string can be "domain.com" or "domain.com:port".
        output_json (Optional[str]): Path to JSON output file, or "-" for stdout.
        output_csv (Optional[str]): Path to CSV output file, or "-" for stdout.
        mode (str): Analysis mode ("simple" or "full").
        insecure (bool): Allow insecure connections (skip cert validation during fetch).
        skip_transparency (bool): Skip crt.sh transparency checks.
        perform_crl_check (bool): Perform CRL checks.
        perform_ocsp_check (bool): Perform OCSP checks.
    """
    logger = logging.getLogger("certcheck")
    results = [] # Changed from all_results to results to match original variable name
    overall_start_time = datetime.datetime.now(timezone.utc)
    # Log the input list directly for clarity
    logger.info(f"Starting analysis for {len(domains_input)} domain entry/entries: {', '.join(domains_input)}")
    logger.info(f"Mode: {mode}, Insecure Fetching: {insecure}, Transparency Check: {not skip_transparency}, CRL Check: {perform_crl_check}, OCSP Check: {perform_ocsp_check}")

    def process_domain(domain_entry_str: str) -> dict:
        parts = domain_entry_str.split(':', 1)
        domain_to_analyze = parts[0]
        port_to_analyze = 443  # Default HTTPS port

        if len(parts) > 1:
            try:
                port_val = int(parts[1])
                if 1 <= port_val <= 65535:
                    port_to_analyze = port_val
                else:
                    logger.warning(
                        f"Port {port_val} for {domain_to_analyze} is out of valid range (1-65535). Using default port 443."
                    )
            except ValueError:
                logger.warning(
                    f"Invalid port format '{parts[1]}' for {domain_to_analyze}. Using default port 443."
                )

        logger.info(
            f"--- Analyzing domain: {domain_to_analyze} on port {port_to_analyze} ---"
        )
        domain_start_time = datetime.datetime.now(timezone.utc)
        try:
            analysis_result = analyze_certificates(
                domain=domain_to_analyze,
                port=port_to_analyze,
                mode=mode,
                insecure=insecure,
                skip_transparency=skip_transparency,
                perform_crl_check=perform_crl_check,
                perform_ocsp_check=perform_ocsp_check,
            )
        except Exception as e:
            analysis_ts = datetime.datetime.now(timezone.utc).isoformat()
            logger.exception(
                f"Unexpected critical error during analysis of {domain_to_analyze}:{port_to_analyze}: {e}"
            )
            analysis_result = {
                "domain": f"{domain_to_analyze}:{port_to_analyze}",
                "analysis_timestamp": analysis_ts,
                "status": "failed",
                "error_message": f"Critical analysis error: {e}",
                "connection_health": {"checked": False, "error": str(e)},
                "validation": {"system_trust_store": None, "error": str(e)},
                "certificates": [],
                "transparency": {"checked": False, "error": str(e)},
                "crl_check": {
                    "checked": perform_crl_check,
                    "leaf_status": "error",
                    "details": {"reason": str(e)},
                },
                "ocsp_check": {
                    "checked": perform_ocsp_check,
                    "status": "error",
                    "details": {"reason": str(e)},
                },
            }
        domain_end_time = datetime.datetime.now(timezone.utc)
        logger.info(
            f"--- Finished analyzing {domain_to_analyze}:{port_to_analyze} in {(domain_end_time - domain_start_time).total_seconds():.2f}s ---"
        )
        return analysis_result

    with ThreadPoolExecutor() as executor:
        results = list(executor.map(process_domain, domains_input))

    overall_end_time = datetime.datetime.now(timezone.utc)
    logger.info(f"Completed analysis of {len(domains_input)} domain entry/entries in {(overall_end_time - overall_start_time).total_seconds():.2f}s")

    if output_json:
        with (open(output_json, 'w') if output_json != '-' else sys.stdout) as f:
            json.dump(results, f, indent=2)
    if output_csv:
        # Ensure this part matches the original structure if it was correct
        with (open(output_csv, 'w', newline='') if output_csv != '-' else sys.stdout) as f:
            writer = csv.writer(f)
            # Using a more robust way to get headers, assuming all results have similar structure
            # This part might need adjustment based on how detailed the CSV needs to be
            # For now, keeping the original extensive header list
            writer.writerow([
                'domain', 'status', 'error_message', 'analysis_timestamp',
                'tls_checked', 'tls_error', 'tls_version', 'supports_tls13', 'cipher_suite',
                'system_trust_store', 'validation_error',
                'crl_checked', 'crl_leaf_status', 'crl_detail',
                'ocsp_checked', 'ocsp_status', 'ocsp_detail', # Added OCSP CSV headers
                'ct_checked', 'ct_total_records', 'ct_errors', 'ct_details',
                'cert_index', 'cert_error', 'subject', 'issuer', 'common_name', 'serial_number', 'version', 'not_before', 'not_after', 'days_remaining',
                'sha256_fingerprint', 'signature_algorithm', 'public_key_algorithm', 'public_key_size', 'profile', 'san', 'has_scts', 'is_ca', 'path_length_constraint'
            ])
            for res_item in results: # Iterate using a different variable name
                trans = res_item.get('transparency', {})
                ct_checked = trans.get('checked', False)
                ct_total_records = trans.get('crtsh_records_found', 0)
                ct_errors = json.dumps(trans.get('errors', {})) if trans.get('errors') else ''
                ct_details_dict = trans.get('details', {})
                ct_details = json.dumps({k: len(v) if v is not None else None for k, v in ct_details_dict.items()}) if ct_details_dict else ''

                certs_list = res_item.get("certificates", [])
                conn_health = res_item.get('connection_health', {})
                validation_info = res_item.get('validation', {})
                crl_info = res_item.get('crl_check', {})
                ocsp_info = res_item.get('ocsp_check', {}) # Get OCSP info

                if not certs_list:
                    writer.writerow([
                        res_item.get('domain'), res_item.get('status'), res_item.get('error_message'), res_item.get('analysis_timestamp'),
                        conn_health.get('checked'), conn_health.get('error'),
                        conn_health.get('tls_version'), conn_health.get('supports_tls13'),
                        conn_health.get('cipher_suite'),
                        validation_info.get('system_trust_store'), validation_info.get('error'),
                        crl_info.get('checked'), crl_info.get('leaf_status'),
                        json.dumps(crl_info.get('details')),
                        ocsp_info.get('checked'), ocsp_info.get('status'), # Added OCSP CSV data
                        json.dumps(ocsp_info.get('details')), # Added OCSP CSV data
                        ct_checked, ct_total_records, ct_errors, ct_details,
                        # Empty certificate fields
                        "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""
                    ])
                else:
                    for cert_item in certs_list: # Iterate using a different variable name
                        writer.writerow([
                            res_item.get('domain'), res_item.get('status'), res_item.get('error_message'), res_item.get('analysis_timestamp'),
                            conn_health.get('checked'), conn_health.get('error'),
                            conn_health.get('tls_version'), conn_health.get('supports_tls13'),
                            conn_health.get('cipher_suite'),
                            validation_info.get('system_trust_store'), validation_info.get('error'),
                            crl_info.get('checked'), crl_info.get('leaf_status'),
                            json.dumps(crl_info.get('details')),
                            ocsp_info.get('checked'), ocsp_info.get('status'), # Added OCSP CSV data
                            json.dumps(ocsp_info.get('details')), # Added OCSP CSV data
                            ct_checked, ct_total_records, ct_errors, ct_details,
                            cert_item.get("chain_index", ""), cert_item.get("error", ""),
                            cert_item.get("subject", ""), cert_item.get("issuer", ""),
                            cert_item.get("common_name", ""), cert_item.get("serial_number", ""),
                            cert_item.get("version", ""), cert_item.get("not_before", ""),
                            cert_item.get("not_after", ""), cert_item.get("days_remaining", ""),
                            cert_item.get("sha256_fingerprint", ""), cert_item.get("signature_algorithm", ""),
                            cert_item.get("public_key_algorithm", ""), cert_item.get("public_key_size_bits", ""),
                            cert_item.get("profile", ""), ", ".join(cert_item.get("san", [])),
                            cert_item.get("has_scts", ""), cert_item.get("is_ca", ""),
                            cert_item.get("path_length_constraint", "")
                        ])
