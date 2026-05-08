# Helper functions for certificate parsing, fingerprints, key details, etc.

import datetime
from datetime import timezone
from typing import Tuple, Optional, List, Union
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

# ---------------------------------------------------------------------------
# OID for Signed Certificate Timestamps (SCT) extension (not in cryptography.x509.ExtensionOID)
# ---------------------------------------------------------------------------
SCT_OID = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")


def calculate_days_remaining(cert: x509.Certificate) -> int:
    """
    Calculates the number of days remaining until the certificate expires.

    Args:
        cert (x509.Certificate): The certificate to check.

    Returns:
        int: Number of days until the certificate expires (can be negative if expired).

    Example:
        >>> days = calculate_days_remaining(cert)
        >>> print(days)
        42
    """
    # Get the current time in UTC
    now_utc = datetime.datetime.now(timezone.utc)

    # Use not_valid_after_utc if available, otherwise fallback to not_valid_after
    expiry_utc = getattr(cert, 'not_valid_after_utc', None)
    if expiry_utc is None:
        expiry_utc = cert.not_valid_after
        # Ensure the expiry date is timezone-aware in UTC
        if expiry_utc.tzinfo is None:
            expiry_utc = expiry_utc.replace(tzinfo=timezone.utc)

    # Calculate the difference in days
    delta = expiry_utc - now_utc
    return delta.days


def get_sha256_fingerprint(cert: x509.Certificate) -> str:
    """
    Returns the SHA-256 fingerprint of the certificate.

    Args:
        cert (x509.Certificate): The certificate to fingerprint.

    Returns:
        str: SHA-256 fingerprint as a hexadecimal string.

    Example:
        >>> fp = get_sha256_fingerprint(cert)
        >>> print(fp)
        'a1b2c3...'
    """
    # Use the fingerprint method from cryptography
    return cert.fingerprint(hashes.SHA256()).hex()


def get_public_key_details(cert: x509.Certificate) -> Tuple[str, Optional[int]]:
    """
    Extracts the public key algorithm and its size from the certificate.

    Args:
        cert (x509.Certificate): The certificate containing the public key.

    Returns:
        Tuple[str, Optional[int]]: Algorithm name and key size in bits (None if unknown).

    Example:
        >>> algo, size = get_public_key_details(cert)
        >>> print(algo, size)
        'RSA', 2048
    """
    public_key = cert.public_key()

    # Check if the public key is of type RSA
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size

    # Check if the public key is of type Elliptic Curve
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = public_key.curve.name if hasattr(public_key.curve, 'name') else 'Unknown Curve'
        return f"ECDSA ({curve_name})", public_key.curve.key_size

    # Check if the public key is of type DSA
    elif isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size

    # Fallback for other key types
    else:
        try:
            # Serialize the public key to PEM to try to infer the algorithm name
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            # Try to extract the algorithm name from the PEM header
            algo_name = pem.decode().split('\n')[0].replace('-----BEGIN PUBLIC KEY-----', '').strip()
            return algo_name if algo_name else "Unknown", None
        except Exception:
            # If serialization fails, return "Unknown"
            return "Unknown", None


def get_signature_algorithm(cert: x509.Certificate) -> str:
    """
    Returns the name of the signature hash algorithm used in the certificate.

    Args:
        cert (x509.Certificate): The certificate to inspect.

    Returns:
        str: Name of the signature hash algorithm, or "Unknown" if not available.

    Example:
        >>> algo = get_signature_algorithm(cert)
        >>> print(algo)
        'sha256'
    """
    # signature_hash_algorithm can be None for some non-standard certificates
    return cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "Unknown"


def has_scts(cert: x509.Certificate) -> bool:
    """
    Checks if the certificate contains Signed Certificate Timestamps (SCTs).

    Args:
        cert (x509.Certificate): The certificate to check.

    Returns:
        bool: True if the SCT extension is present, False otherwise.

    Example:
        >>> has = has_scts(cert)
        >>> print(has)
        True
    """
    try:
        # Search for the SCT extension by its OID
        ext = cert.extensions.get_extension_for_oid(SCT_OID)
        return ext is not None
    except Exception:
        # Extension not found or error
        return False


def extract_san(cert: x509.Certificate) -> List[str]:
    """
    Extracts DNS names from the Subject Alternative Name (SAN) field of the certificate.

    Args:
        cert (x509.Certificate): The certificate to analyze.

    Returns:
        List[str]: List of DNS names in the SAN extension, or an empty list if none are found.

    Example:
        >>> sans = extract_san(cert)
        >>> print(sans)
        ['example.com', 'www.example.com']
    """
    try:
        # Search for the SAN extension by its OID
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = ext.value
        if isinstance(san, x509.SubjectAlternativeName):
            # Return all DNSNames present in the SAN
            return san.get_values_for_type(x509.DNSName)
        else:
            return []
    except Exception:
        # SAN extension not found or error
        return []


def assess_cert_quality(cert: x509.Certificate) -> List[str]:
    """
    Return a list of human-readable quality warnings for a certificate.

    Inspects the certificate's public key (algorithm, size/curve) and
    signature hash algorithm and emits one warning per detected
    weakness. An empty list means no issues were detected at the
    algorithm/key-strength level.

    The following situations trigger a warning:

    - **RSA key < 2048 bits**: ``"Weak RSA key: <size> bits (recommended >= 2048)"``.
    - **ECDSA curve < P-256** (i.e. ``key_size`` < 256):
      ``"Weak ECDSA curve: <curve_name> (recommended >= P-256)"``.
    - **DSA public key**: ``"Deprecated DSA key (use RSA or ECDSA)"`` —
      regardless of size; DSA is no longer recommended for TLS.
    - **SHA-1 signature**: ``"Deprecated signature algorithm: sha1"``.
    - **MD5 / MD2 / MD4 signature**: ``"Insecure signature algorithm: <name>"``.

    Parameters
    ----------
    cert : x509.Certificate
        The certificate to assess.

    Returns
    -------
    List[str]
        Quality warnings, possibly empty.

    Examples
    --------
    >>> warnings = assess_cert_quality(cert)
    >>> if warnings:
    ...     for w in warnings:
    ...         print("WARN:", w)
    """
    warnings: List[str] = []

    public_key = cert.public_key()

    # Public-key strength checks. ``isinstance`` matches the order used
    # in :func:`get_public_key_details` so behaviour stays consistent.
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < 2048:
            warnings.append(
                f"Weak RSA key: {public_key.key_size} bits (recommended >= 2048)"
            )
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_size = public_key.curve.key_size
        if curve_size < 256:
            curve_name = getattr(public_key.curve, "name", "unknown") or "unknown"
            warnings.append(
                f"Weak ECDSA curve: {curve_name} (recommended >= P-256)"
            )
    elif isinstance(public_key, dsa.DSAPublicKey):
        warnings.append("Deprecated DSA key (use RSA or ECDSA)")

    # Signature hash algorithm checks. ``signature_hash_algorithm`` may
    # be ``None`` for some non-standard certificates (e.g. Ed25519).
    sig_algo = cert.signature_hash_algorithm
    if sig_algo is not None:
        sig_name = sig_algo.name.lower()
        if sig_name == "sha1":
            warnings.append("Deprecated signature algorithm: sha1")
        elif sig_name in {"md5", "md2", "md4"}:
            warnings.append(f"Insecure signature algorithm: {sig_name}")

    return warnings


def get_common_name(subject: x509.Name) -> Optional[str]:
    """
    Retrieves the Common Name (CN) from the subject of a certificate.

    Args:
        subject (x509.Name): The subject field of the certificate.

    Returns:
        Optional[str]: The Common Name if found, otherwise None.

    Example:
        >>> cn = get_common_name(cert.subject)
        >>> print(cn)
        'example.com'
    """
    # Iterate through all attributes of the subject to find the CN
    for attribute in subject:
        if attribute.oid == x509.NameOID.COMMON_NAME:
            value = attribute.value
            # Always return a string, decode if necessary
            if isinstance(value, str):
                return value
            if isinstance(value, bytes):
                return value.decode('utf-8', errors='ignore')
            if isinstance(value, (bytearray, memoryview)):
                return bytes(value).decode('utf-8', errors='ignore')
            return str(value)
    return None
