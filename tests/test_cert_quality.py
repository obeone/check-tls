"""Tests for :func:`check_tls.utils.cert_utils.assess_cert_quality`."""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from check_tls.utils.cert_utils import assess_cert_quality


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_cert(public_key, signing_key, sign_algo=hashes.SHA256()):
    """
    Build a minimal x509 certificate carrying ``public_key``, signed
    with ``signing_key`` using ``sign_algo``.

    Used to vary key types/sizes and signature algorithms in tests.
    """
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    return builder.sign(signing_key, sign_algo)


class _FakeSigAlgo:
    """Duck-typed object with a ``name`` attribute, used to spoof
    :attr:`x509.Certificate.signature_hash_algorithm` so the SHA-1 /
    MD5 paths can be exercised without asking ``cryptography`` to
    actually sign with those (forbidden) hashes."""

    def __init__(self, name):
        self.name = name


class _CertProxy:
    """Wrap a real certificate but override ``signature_hash_algorithm``."""

    def __init__(self, real_cert, fake_sig_name):
        self._real = real_cert
        self._fake = _FakeSigAlgo(fake_sig_name)

    @property
    def signature_hash_algorithm(self):
        return self._fake

    def public_key(self):
        return self._real.public_key()


# ---------------------------------------------------------------------------
# Public-key strength
# ---------------------------------------------------------------------------

def test_rsa_1024_emits_weak_warning():
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    cert = _build_cert(key.public_key(), key)
    warnings = assess_cert_quality(cert)
    assert any("Weak RSA key: 1024 bits" in w for w in warnings)


def test_rsa_2048_is_clean():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _build_cert(key.public_key(), key)
    assert assess_cert_quality(cert) == []


def test_ecdsa_p192_emits_weak_warning():
    key = ec.generate_private_key(ec.SECP192R1())
    # ECDSA cannot sign with SHA-256 in some constrained builds; use
    # SHA-256 directly which is still acceptable for SECP192R1.
    cert = _build_cert(key.public_key(), key, hashes.SHA256())
    warnings = assess_cert_quality(cert)
    assert any("Weak ECDSA curve" in w for w in warnings)


def test_ecdsa_p256_is_clean():
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _build_cert(key.public_key(), key, hashes.SHA256())
    assert assess_cert_quality(cert) == []


def test_dsa_emits_deprecated_warning():
    # DSA at 2048 bits — still flagged because DSA itself is deprecated
    # for TLS regardless of size.
    dsa_key = dsa.generate_private_key(key_size=2048)
    rsa_signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _build_cert(dsa_key.public_key(), rsa_signer)
    warnings = assess_cert_quality(cert)
    assert any("Deprecated DSA key" in w for w in warnings)


# ---------------------------------------------------------------------------
# Signature hash algorithm
# ---------------------------------------------------------------------------

def test_sha1_signature_emits_deprecated_warning():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _build_cert(key.public_key(), key)
    proxy = _CertProxy(cert, "sha1")
    warnings = assess_cert_quality(proxy)
    assert any("Deprecated signature algorithm: sha1" in w for w in warnings)


def test_md5_signature_emits_insecure_warning():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _build_cert(key.public_key(), key)
    proxy = _CertProxy(cert, "md5")
    warnings = assess_cert_quality(proxy)
    assert any("Insecure signature algorithm: md5" in w for w in warnings)


def test_sha256_signature_is_clean():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _build_cert(key.public_key(), key, hashes.SHA256())
    assert assess_cert_quality(cert) == []


def test_combined_weak_key_and_weak_sig_emits_two_warnings():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    cert = _build_cert(rsa_key.public_key(), rsa_key)
    proxy = _CertProxy(cert, "sha1")
    warnings = assess_cert_quality(proxy)
    assert any("Weak RSA key" in w for w in warnings)
    assert any("Deprecated signature algorithm: sha1" in w for w in warnings)
    assert len(warnings) == 2
