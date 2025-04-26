# Helper functions for certificate parsing, fingerprints, key details, etc.

import datetime
from datetime import timezone
from typing import Tuple, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa


def calculate_days_remaining(cert: x509.Certificate) -> int:
    now_utc = datetime.datetime.now(timezone.utc)
    # Use not_valid_after_utc if available, otherwise fallback
    expiry_utc = getattr(cert, 'not_valid_after_utc', None)
    if expiry_utc is None:
        expiry_utc = cert.not_valid_after
        if expiry_utc.tzinfo is None:
            expiry_utc = expiry_utc.replace(tzinfo=timezone.utc)
    delta = expiry_utc - now_utc
    return delta.days


def get_sha256_fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def get_public_key_details(cert: x509.Certificate) -> Tuple[str, Optional[int]]:
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = public_key.curve.name if hasattr(public_key.curve, 'name') else 'Unknown Curve'
        return f"ECDSA ({curve_name})", public_key.curve.key_size
    elif isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    else:
        try:
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            algo_name = pem.decode().split('\n')[0].replace('-----BEGIN PUBLIC KEY-----', '').strip()
            return algo_name if algo_name else "Unknown", None
        except Exception:
            return "Unknown", None


def get_signature_algorithm(cert: x509.Certificate) -> str:
    return cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "Unknown"


def has_scts(cert: x509.Certificate) -> bool:
    try:
        ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMP_LIST)
        return ext is not None
    except Exception:
        return False


def extract_san(cert: x509.Certificate):
    try:
        ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        return []


def get_common_name(subject: x509.Name):
    for attribute in subject:
        if attribute.oid == x509.NameOID.COMMON_NAME:
            return attribute.value
    return None
