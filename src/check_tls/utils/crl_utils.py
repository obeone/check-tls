"""
crl_utils.py

Utility functions for downloading, parsing, and checking Certificate Revocation Lists (CRLs).
Provides helpers to fetch CRLs from URIs, parse them, and check the revocation status of certificates.
"""

import urllib.request
import logging
import datetime
from datetime import timezone
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, CRLEntryExtensionOID
from typing import Optional, Dict, Any
import urllib.parse

# Timeout in seconds for CRL HTTP requests
CRL_TIMEOUT = 10


def download_crl(url: str) -> Optional[bytes]:
    """
    Download a Certificate Revocation List (CRL) from the given URL.

    Args:
        url (str): The URL to fetch the CRL from.

    Returns:
        Optional[bytes]: The raw CRL data if successful, None otherwise.

    Example:
        crl_data = download_crl("http://example.com/crl.pem")
    """
    try:
        req = urllib.request.Request(
            url, headers={'User-Agent': 'Python-CertCheck/1.3'}
        )
        with urllib.request.urlopen(req, timeout=CRL_TIMEOUT) as response:
            if response.status == 200:
                return response.read()
            else:
                return None
    except Exception as e:
        # Could log the exception here if needed
        return None


def parse_crl(crl_data: bytes) -> Optional[x509.CertificateRevocationList]:
    """
    Parse CRL data in DER or PEM format.

    Args:
        crl_data (bytes): The raw CRL data.

    Returns:
        Optional[x509.CertificateRevocationList]: Parsed CRL object if successful, None otherwise.

    Example:
        crl = parse_crl(crl_data)
    """
    try:
        # Try DER format first
        return x509.load_der_x509_crl(crl_data, default_backend())
    except Exception:
        try:
            # Fallback to PEM format
            return x509.load_pem_x509_crl(crl_data, default_backend())
        except Exception:
            return None


def check_crl(cert: x509.Certificate) -> Dict[str, Any]:
    """
    Check the revocation status of a certificate using its CRL Distribution Points.

    Args:
        cert (x509.Certificate): The certificate to check.

    Returns:
        Dict[str, Any]: Dictionary with keys:
            - 'status': One of 'good', 'revoked', 'crl_expired', 'unreachable', 'parse_error', 'no_cdp', 'no_http_cdp', 'error', or 'unknown'
            - 'checked_uri': The URI of the CRL checked (if any)
            - 'reason': Additional information or error message

    Example:
        result = check_crl(cert)
        if result['status'] == 'revoked':
            print("Certificate is revoked!")
    """
    logger = logging.getLogger("certcheck")
    result = {"status": "unknown", "checked_uri": None, "reason": None}
    now_utc = datetime.datetime.now(timezone.utc)

    # Try to extract CRL Distribution Points extension
    try:
        cdp_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        cdp_value = cdp_ext.value
    except x509.ExtensionNotFound:
        logger.info(f"No CRL Distribution Points extension found for cert S/N {hex(cert.serial_number)}")
        result["status"] = "no_cdp"
        result["reason"] = "No CRL Distribution Point extension in certificate."
        return result
    except Exception as e:
        logger.warning(f"Error accessing CRL Distribution Points for cert S/N {hex(cert.serial_number)}: {e}")
        result["status"] = "error"
        result["reason"] = f"Error accessing CDP extension: {e}"
        return result

    # Collect HTTP(S) URIs from the CRL Distribution Points
    http_cdp_uris = []
    # cdp_value should be an instance of x509.CRLDistributionPoints.
    # x509.CRLDistributionPoints is a Sequence[DistributionPoint], so it's directly iterable.
    if isinstance(cdp_value, x509.CRLDistributionPoints):
        for point in cdp_value: # Iterate directly over the CRLDistributionPoints sequence
            if point.full_name:
                for general_name in point.full_name:
                    if isinstance(general_name, x509.UniformResourceIdentifier):
                        uri = general_name.value
                        parsed_uri = urllib.parse.urlparse(uri)
                        if parsed_uri.scheme in ["http", "https"]:
                            http_cdp_uris.append(uri)
                        # else: # Optional: log non-HTTP URIs if needed for debugging in the future
                            # logger.debug(f"Found non-HTTP(S) CDP URI: {uri} with scheme: {parsed_uri.scheme} for cert S/N {hex(cert.serial_number)}")
    else:
        logger.warning(
            f"CRLDistributionPoints extension value has unexpected type for cert S/N {hex(cert.serial_number)}: {type(cdp_value)}. Expected x509.CRLDistributionPoints."
        )
        # If cdp_value is not of the expected type, http_cdp_uris will remain empty,
        # and the 'no_http_cdp' status will be set below.

    if not http_cdp_uris:
        logger.warning(f"No HTTP(S) CRL Distribution Points found for cert S/N {hex(cert.serial_number)}")
        result["status"] = "no_http_cdp"
        if not isinstance(cdp_value, x509.CRLDistributionPoints):
            result["reason"] = "CRL Distribution Points extension has an unexpected format or type."
        else:
            result["reason"] = "No HTTP(S) URIs found in CRL Distribution Points."
        return result

    logger.info(
        f"Found {len(http_cdp_uris)} HTTP(S) CDP URIs for cert S/N {hex(cert.serial_number)}: {', '.join(http_cdp_uris)}"
    )

    # Try each HTTP(S) CRL URI in order
    for uri in http_cdp_uris:
        result["checked_uri"] = uri
        crl_data = download_crl(uri)
        if crl_data is None:
            result["status"] = "unreachable"
            result["reason"] = f"Failed to download CRL from {uri}"
            continue

        crl = parse_crl(crl_data)
        if crl is None:
            result["status"] = "parse_error"
            result["reason"] = f"Failed to parse CRL downloaded from {uri}"
            continue

        # Use next_update_utc if available (for deprecation warning fix)
        next_update = getattr(crl, 'next_update_utc', None)
        if next_update is None:
            logger.warning(f"CRL from {uri} has no next update time. Cannot check expiry.")
        elif next_update < now_utc:
            logger.warning(f"CRL from {uri} has expired (Next Update: {next_update}).")
            result["status"] = "crl_expired"
            result["reason"] = f"CRL expired on {next_update}"
            continue

        # Check if the certificate is revoked
        revoked_entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if revoked_entry is not None:
            revocation_date = getattr(revoked_entry, 'revocation_date', None)
            logger.warning(
                f"Certificate S/N {hex(cert.serial_number)} IS REVOKED according to CRL from {uri} (Revoked on: {revocation_date})"
            )
            result["status"] = "revoked"
            result["reason"] = f"Certificate serial number found in CRL (Revoked on: {revocation_date})"
            try:
                # Find the CRL reason extension in the revoked certificate's extensions (if available)
                crl_reason = None
                if hasattr(revoked_entry, "extensions"):
                    for ext in getattr(revoked_entry, "extensions", []):
                        if isinstance(ext.value, x509.CRLReason):
                            crl_reason = ext.value
                            break
                if crl_reason is not None:
                    result["reason"] += f" Reason: {crl_reason.reason.name}"
            except x509.ExtensionNotFound:
                # No reason code present
                pass
            except Exception as ext_e:
                logger.warning(f"Could not read CRL entry reason code: {ext_e}")
            return result
        else:
            logger.info(
                f"Certificate S/N {hex(cert.serial_number)} is not revoked according to CRL from {uri}"
            )
            result["status"] = "good"
            result["reason"] = "Certificate serial number not found in valid CRL."
            return result

    # If none of the URIs provided a definitive answer
    if result["status"] == "unknown":
        result["reason"] = "Could not determine revocation status from any CDP URI."
    return result
