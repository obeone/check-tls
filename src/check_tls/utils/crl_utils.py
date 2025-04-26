# CRL check/download/parse functions

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

CRL_TIMEOUT = 10


def download_crl(url: str):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Python-CertCheck/1.3'})
        with urllib.request.urlopen(req, timeout=CRL_TIMEOUT) as response:
            if response.status == 200:
                return response.read()
            else:
                return None
    except Exception as e:
        return None

def parse_crl(crl_data: bytes):
    try:
        return x509.load_der_x509_crl(crl_data, default_backend())
    except Exception:
        try:
            return x509.load_pem_x509_crl(crl_data, default_backend())
        except Exception:
            return None

def check_crl(cert: x509.Certificate) -> Dict[str, Any]:
    """
    Checks the revocation status of a certificate using its CRL Distribution Points.
    Returns a dictionary with status and details.
    """
    logger = logging.getLogger("certcheck")
    result = {"status": "unknown", "checked_uri": None, "reason": None}
    now_utc = datetime.datetime.now(timezone.utc)

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

    http_cdp_uris = []
    for point in cdp_value:
        if point.full_name:
            for general_name in point.full_name:
                if isinstance(general_name, x509.UniformResourceIdentifier):
                    uri = general_name.value
                    parsed_uri = urllib.parse.urlparse(uri)
                    if parsed_uri.scheme in ["http", "https"]:
                        http_cdp_uris.append(uri)

    if not http_cdp_uris:
        logger.warning(f"No HTTP(S) CRL Distribution Points found for cert S/N {hex(cert.serial_number)}")
        result["status"] = "no_http_cdp"
        result["reason"] = "No HTTP(S) URIs found in CRL Distribution Points."
        return result

    logger.info(f"Found {len(http_cdp_uris)} HTTP(S) CDP URIs for cert S/N {hex(cert.serial_number)}: {', '.join(http_cdp_uris)}")

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

        # Use next_update_utc for deprecation warning fix
        next_update = getattr(crl, 'next_update_utc', None)
        if next_update is None:
            logger.warning(f"CRL from {uri} has no next update time. Cannot check expiry.")
        elif next_update < now_utc:
            logger.warning(f"CRL from {uri} has expired (Next Update: {next_update}).")
            result["status"] = "crl_expired"
            result["reason"] = f"CRL expired on {next_update}"
            continue

        # Check revocation
        revoked_entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if revoked_entry is not None:
            revocation_date = getattr(revoked_entry, 'revocation_date', None)
            logger.warning(f"Certificate S/N {hex(cert.serial_number)} IS REVOKED according to CRL from {uri} (Revoked on: {revocation_date})")
            result["status"] = "revoked"
            result["reason"] = f"Certificate serial number found in CRL (Revoked on: {revocation_date})"
            try:
                reason_ext = revoked_entry.extensions.get_extension_for_oid(CRLEntryExtensionOID.REASON_CODE)
                result["reason"] += f" Reason: {reason_ext.value.reason.name}"
            except x509.ExtensionNotFound:
                pass
            except Exception as ext_e:
                logger.warning(f"Could not read CRL entry reason code: {ext_e}")
            return result
        else:
            logger.info(f"Certificate S/N {hex(cert.serial_number)} is not revoked according to CRL from {uri}")
            result["status"] = "good"
            result["reason"] = "Certificate serial number not found in valid CRL."
            return result

    if result["status"] == "unknown":
        result["reason"] = "Could not determine revocation status from any CDP URI."
    return result
