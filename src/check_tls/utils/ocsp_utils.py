# -*- coding: utf-8 -*-
"""
OCSP Utilities for check-tls.

This module provides functions to handle OCSP (Online Certificate Status Protocol)
checks for X.509 certificates.
"""
from typing import Any, Dict, List, Optional

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID # Import ExtensionOID


def get_ocsp_urls(cert: x509.Certificate) -> List[str]:
    """
    Extract OCSP URLs from the Authority Information Access extension of a certificate.

    Args:
        cert: The x509.Certificate object to extract OCSP URLs from.

    Returns:
        A list of OCSP URLs found in the certificate. Returns an empty list if no
        OCSP URLs are found or the extension is not present.

    Example:
        >>> # Assuming 'certificate' is a loaded x509.Certificate object
        >>> # urls = get_ocsp_urls(certificate)
        >>> # print(urls)
        [] # Or ['http://ocsp.example.com']
    """
    ocsp_urls = []
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS # Use imported ExtensionOID
        )
        if aia and aia.value:
            # aia.value should be a list of AccessDescription objects
            for desc in aia.value: # type: ignore
                if desc.access_method == AuthorityInformationAccessOID.OCSP:
                    if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                        ocsp_urls.append(desc.access_location.value)
    except x509.ExtensionNotFound:
        pass  # No AIA extension found
    return ocsp_urls


def build_ocsp_request(
    cert: x509.Certificate, issuer_cert: x509.Certificate
) -> bytes:
    """
    Build a DER-encoded OCSP request.

    Args:
        cert: The x509.Certificate for which the status is being requested.
        issuer_cert: The x509.Certificate of the issuer of 'cert'.

    Returns:
        The DER-encoded OCSP request as bytes.

    Example:
        >>> # Assuming 'certificate' and 'issuer_certificate' are loaded
        >>> # ocsp_req_bytes = build_ocsp_request(certificate, issuer_certificate)
        >>> # print(len(ocsp_req_bytes) > 0)
        True
    """
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(
        cert, issuer_cert, hashes.SHA1()
    )  # SHA1 is common for OCSP
    req = builder.build()
    return req.public_bytes(serialization.Encoding.DER)


def fetch_ocsp_response(url: str, request_data: bytes) -> Optional[bytes]:
    """
    Fetch an OCSP response from the given URL using an HTTP POST request.

    Args:
        url: The URL of the OCSP responder.
        request_data: The DER-encoded OCSP request bytes.

    Returns:
        The raw OCSP response as bytes if the request is successful (HTTP 200),
        otherwise None.

    Example:
        >>> # Assuming 'ocsp_url' and 'ocsp_request_bytes' are available
        >>> # response_bytes = fetch_ocsp_response(ocsp_url, ocsp_request_bytes)
        >>> # if response_bytes:
        >>> #     print("OCSP response received.")
        >>> # else:
        >>> #     print("Failed to fetch OCSP response.")
        OCSP response received. # Or Failed to fetch OCSP response.
    """
    try:
        headers = {"Content-Type": "application/ocsp-request"}
        response = requests.post(url, data=request_data, headers=headers, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        if response.status_code == 200:
            return response.content
    except requests.exceptions.RequestException:
        # Covers connection errors, timeouts, HTTP errors, etc.
        pass
    return None


def parse_ocsp_response(data: bytes) -> Dict[str, Any]:
    """
    Parse a DER-encoded OCSP response.

    Args:
        data: The DER-encoded OCSP response bytes.

    Returns:
        A dictionary containing the parsed OCSP response details.
        Keys include 'status', 'this_update', 'next_update', 'revocation_time',
        'revocation_reason', and 'responder_id'.
        Returns a dictionary with 'status': 'error' and 'error_message' if parsing fails.

    Example:
        >>> # Assuming 'ocsp_response_bytes' contains a valid OCSP response
        >>> # parsed_info = parse_ocsp_response(ocsp_response_bytes)
        >>> # print(parsed_info['status'])
        good # Or revoked, unknown, error
    """
    result: Dict[str, Any] = {"status": "error"}
    try:
        ocsp_resp = ocsp.load_der_ocsp_response(data)

        if ocsp_resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            result["error_message"] = (
                f"OCSP response status not successful: {ocsp_resp.response_status.name}"
            )
            return result

        # Convert iterator to list to check length and access by index
        # Do this early before checking its length or content.
        list_of_responses = list(ocsp_resp.responses)

        # Assuming a single response, which is typical
        if not ocsp_resp.certificates and len(list_of_responses) == 0:
             result["error_message"] = "OCSP response contains no actual certificate status."
             return result

        # For simplicity, we take the first response if multiple are present.
        # A more robust implementation might need to match the request.

        if not list_of_responses: # Check if the list is empty
            result["error_message"] = "No individual responses found in OCSP response."
            return result

        # Let's assume we are interested in the first response in the list
        single_resp_entry = list_of_responses[0]


        if single_resp_entry.certificate_status == ocsp.OCSPCertStatus.GOOD:
            result["status"] = "good"
        elif single_resp_entry.certificate_status == ocsp.OCSPCertStatus.REVOKED:
            result["status"] = "revoked"
            if single_resp_entry.revocation_time_utc: # Changed from revocation_time
                result["revocation_time"] = single_resp_entry.revocation_time_utc.isoformat()
            if single_resp_entry.revocation_reason:
                result["revocation_reason"] = single_resp_entry.revocation_reason.name
        elif single_resp_entry.certificate_status == ocsp.OCSPCertStatus.UNKNOWN:
            result["status"] = "unknown"
        else:
            result["status"] = "error" # Should not happen if status is SUCCESSFUL
            result["error_message"] = f"Unexpected certificate status: {single_resp_entry.certificate_status}"


        result["this_update"] = single_resp_entry.this_update_utc.isoformat() # Changed from this_update
        if single_resp_entry.next_update_utc: # Changed from next_update
            result["next_update"] = single_resp_entry.next_update_utc.isoformat() # Changed from next_update
        else:
            result["next_update"] = None

        # Responder ID
        if ocsp_resp.responder_name:
            # This is an X501Name, convert to string
            result["responder_id"] = ocsp_resp.responder_name.rfc4514_string()
        elif ocsp_resp.responder_key_hash:
            # This is bytes, convert to hex
            result["responder_id"] = ocsp_resp.responder_key_hash.hex()
        else:
            result["responder_id"] = "N/A"

    except ValueError as e:
        result["error_message"] = f"Failed to parse OCSP response: {str(e)}"
    except Exception as e: # Catch any other unexpected errors during parsing
        result["status"] = "error"
        result["error_message"] = f"An unexpected error occurred during OCSP parsing: {str(e)}"

    return result


def check_ocsp(
    cert: x509.Certificate, issuer_cert: x509.Certificate
) -> Dict[str, Any]:
    """
    Orchestrates the OCSP check for a given certificate.

    It gets OCSP URLs, builds the request, fetches the response, parses it,
    and returns a summary.

    Args:
        cert: The x509.Certificate to check.
        issuer_cert: The x509.Certificate of the issuer of 'cert'.

    Returns:
        A dictionary with the OCSP check result:
        {
            "checked_url": str (the URL used for the check, or "N/A"),
            "status": str ("good", "revoked", "unknown", "error", "no_ocsp_url",
                           "fetch_failed", "parse_failed"),
            "details": Dict (the parsed OCSP response or error details)
        }

    Example:
        >>> # Assuming 'certificate' and 'issuer_certificate' are loaded
        >>> # ocsp_status = check_ocsp(certificate, issuer_certificate)
        >>> # print(ocsp_status['status'])
        good # Or other statuses like 'revoked', 'no_ocsp_url', etc.
    """
    ocsp_urls = get_ocsp_urls(cert)
    if not ocsp_urls:
        return {
            "checked_url": "N/A",
            "status": "no_ocsp_url",
            "details": {"message": "No OCSP URLs found in the certificate."},
        }

    # Try the first URL, a more robust implementation might try multiple
    ocsp_url = ocsp_urls[0]
    result: Dict[str, Any] = {
        "checked_url": ocsp_url,
        "status": "error", # Default status
        "details": {},
    }

    try:
        request_bytes = build_ocsp_request(cert, issuer_cert)
    except Exception as e:
        result["status"] = "build_request_failed"
        result["details"] = {"message": f"Failed to build OCSP request: {str(e)}"}
        return result

    response_bytes = fetch_ocsp_response(ocsp_url, request_bytes)
    if response_bytes is None:
        result["status"] = "fetch_failed"
        result["details"] = {"message": f"Failed to fetch OCSP response from {ocsp_url}."}
        return result

    try:
        parsed_response = parse_ocsp_response(response_bytes)
        result["details"] = parsed_response
        # Propagate the status from parse_ocsp_response if it's not 'error'
        # or if it is 'error' but has a specific message.
        if "status" in parsed_response:
            if parsed_response["status"] != "error" or "error_message" in parsed_response :
                 result["status"] = parsed_response["status"]
            else: # if status is 'error' without specific message, mark as parse_failed
                 result["status"] = "parse_failed"
        else: # Should not happen if parse_ocsp_response behaves as expected
            result["status"] = "parse_failed"
            result["details"]["message"] = "Parsing did not return a status."

    except Exception as e: # Catch-all for unexpected errors during parsing integration
        result["status"] = "parse_failed"
        result["details"] = {"message": f"An unexpected error occurred while processing OCSP response: {str(e)}"}

    return result

if __name__ == '__main__':
    # This is a placeholder for potential command-line testing or examples.
    # For actual testing, use a proper testing framework and mock certificates/responders.
    print("OCSP Utilities module. Not meant to be run directly without test data.")

    # Example of how one might try to use it (requires actual cert files or objects)
    # from cryptography.hazmat.backends import default_backend
    #
    # def load_cert_from_file(filepath):
    #     with open(filepath, "rb") as f:
    #         cert_data = f.read()
    #     return x509.load_pem_x509_certificate(cert_data, default_backend())
    #
    # try:
    #     # Replace with actual paths to PEM encoded certificate files
    #     # leaf_cert = load_cert_from_file("path/to/your/leaf_cert.pem")
    #     # issuer_cert = load_cert_from_file("path/to/your/issuer_cert.pem")
    #
    #     # print(f"Checking OCSP for: {leaf_cert.subject.rfc4514_string()}")
    #     # ocsp_result = check_ocsp(leaf_cert, issuer_cert)
    #     # import json
    #     # print(json.dumps(ocsp_result, indent=2))
    #
    # except FileNotFoundError:
    #     print("Please provide valid paths to certificate files for testing.")
    # except Exception as e:
    #     print(f"An error occurred during example execution: {e}")
    pass
