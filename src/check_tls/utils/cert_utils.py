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
    Calcule le nombre de jours restants avant l'expiration du certificat.

    Args:
        cert (x509.Certificate): Le certificat à vérifier.

    Returns:
        int: Nombre de jours avant l'expiration du certificat (peut être négatif si expiré).

    Example:
        >>> days = calculate_days_remaining(cert)
        >>> print(days)
        42
    """
    # Obtenir la date/heure actuelle en UTC
    now_utc = datetime.datetime.now(timezone.utc)

    # Utiliser not_valid_after_utc si disponible, sinon fallback sur not_valid_after
    expiry_utc = getattr(cert, 'not_valid_after_utc', None)
    if expiry_utc is None:
        expiry_utc = cert.not_valid_after
        # S'assurer que la date d'expiration est timezone-aware en UTC
        if expiry_utc.tzinfo is None:
            expiry_utc = expiry_utc.replace(tzinfo=timezone.utc)

    # Calculer la différence en jours
    delta = expiry_utc - now_utc
    return delta.days


def get_sha256_fingerprint(cert: x509.Certificate) -> str:
    """
    Retourne l'empreinte SHA-256 du certificat.

    Args:
        cert (x509.Certificate): Le certificat à fingerprint.

    Returns:
        str: Empreinte SHA-256 sous forme de chaîne hexadécimale.

    Example:
        >>> fp = get_sha256_fingerprint(cert)
        >>> print(fp)
        'a1b2c3...'
    """
    # Utilise la méthode fingerprint de cryptography
    return cert.fingerprint(hashes.SHA256()).hex()


def get_public_key_details(cert: x509.Certificate) -> Tuple[str, Optional[int]]:
    """
    Extrait l'algorithme de la clé publique et sa taille à partir du certificat.

    Args:
        cert (x509.Certificate): Le certificat contenant la clé publique.

    Returns:
        Tuple[str, Optional[int]]: Nom de l'algorithme et taille de la clé en bits (None si inconnu).

    Example:
        >>> algo, size = get_public_key_details(cert)
        >>> print(algo, size)
        'RSA', 2048
    """
    public_key = cert.public_key()

    # Vérifie si la clé publique est de type RSA
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size

    # Vérifie si la clé publique est de type Elliptic Curve
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = public_key.curve.name if hasattr(public_key.curve, 'name') else 'Unknown Curve'
        return f"ECDSA ({curve_name})", public_key.curve.key_size

    # Vérifie si la clé publique est de type DSA
    elif isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size

    # Fallback pour d'autres types de clés
    else:
        try:
            # Sérialise la clé publique en PEM pour tenter d'inférer le nom de l'algorithme
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            # Tente d'extraire le nom de l'algorithme depuis l'en-tête PEM
            algo_name = pem.decode().split('\n')[0].replace('-----BEGIN PUBLIC KEY-----', '').strip()
            return algo_name if algo_name else "Unknown", None
        except Exception:
            # Si la sérialisation échoue, retourne "Unknown"
            return "Unknown", None


def get_signature_algorithm(cert: x509.Certificate) -> str:
    """
    Retourne le nom de l'algorithme de hachage de la signature utilisé dans le certificat.

    Args:
        cert (x509.Certificate): Le certificat à inspecter.

    Returns:
        str: Nom de l'algorithme de hachage de la signature, ou "Unknown" si non disponible.

    Example:
        >>> algo = get_signature_algorithm(cert)
        >>> print(algo)
        'sha256'
    """
    # signature_hash_algorithm peut être None pour certains certificats non standards
    return cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "Unknown"


def has_scts(cert: x509.Certificate) -> bool:
    """
    Vérifie si le certificat contient des Signed Certificate Timestamps (SCTs).

    Args:
        cert (x509.Certificate): Le certificat à vérifier.

    Returns:
        bool: True si l'extension SCT est présente, False sinon.

    Example:
        >>> has = has_scts(cert)
        >>> print(has)
        True
    """
    try:
        # Recherche l'extension SCT par son OID
        ext = cert.extensions.get_extension_for_oid(SCT_OID)
        return ext is not None
    except Exception:
        # Extension non trouvée ou erreur
        return False


def extract_san(cert: x509.Certificate) -> List[str]:
    """
    Extrait les noms DNS du champ Subject Alternative Name (SAN) du certificat.

    Args:
        cert (x509.Certificate): Le certificat à analyser.

    Returns:
        List[str]: Liste des noms DNS dans l'extension SAN, ou liste vide si aucun trouvé.

    Example:
        >>> sans = extract_san(cert)
        >>> print(sans)
        ['example.com', 'www.example.com']
    """
    try:
        # Recherche l'extension SAN par son OID
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = ext.value
        if isinstance(san, x509.SubjectAlternativeName):
            # Retourne tous les DNSName présents dans le SAN
            return san.get_values_for_type(x509.DNSName)
        else:
            return []
    except Exception:
        # Extension SAN non trouvée ou erreur
        return []


def get_common_name(subject: x509.Name) -> Optional[str]:
    """
    Récupère le Common Name (CN) depuis le subject d'un certificat.

    Args:
        subject (x509.Name): Le champ subject du certificat.

    Returns:
        Optional[str]: Le Common Name si trouvé, sinon None.

    Example:
        >>> cn = get_common_name(cert.subject)
        >>> print(cn)
        'example.com'
    """
    # Parcourt tous les attributs du subject pour trouver le CN
    for attribute in subject:
        if attribute.oid == x509.NameOID.COMMON_NAME:
            value = attribute.value
            # Retourne toujours une chaîne, décode si nécessaire
            if isinstance(value, str):
                return value
            if isinstance(value, bytes):
                return value.decode('utf-8', errors='ignore')
            if isinstance(value, (bytearray, memoryview)):
                return bytes(value).decode('utf-8', errors='ignore')
            return str(value)
    return None
