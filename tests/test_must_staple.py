"""Tests for :func:`check_tls.utils.cert_utils.has_must_staple`."""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import TLSFeature, TLSFeatureType

from check_tls.utils.cert_utils import has_must_staple


def _build_cert(extensions):
    """Build a self-signed RSA cert carrying the given extensions."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    for ext, critical in extensions:
        builder = builder.add_extension(ext, critical=critical)
    return builder.sign(key, hashes.SHA256())


def test_has_must_staple_true_when_status_request_present():
    cert = _build_cert(
        [(TLSFeature(features=[TLSFeatureType.status_request]), False)]
    )
    assert has_must_staple(cert) is True


def test_has_must_staple_false_without_extension():
    cert = _build_cert([])
    assert has_must_staple(cert) is False


def test_has_must_staple_false_with_status_request_v2_only():
    """Only the integer 5 (status_request) qualifies as Must-Staple;
    status_request_v2 (17) does not."""
    cert = _build_cert(
        [(TLSFeature(features=[TLSFeatureType.status_request_v2]), False)]
    )
    assert has_must_staple(cert) is False


def test_has_must_staple_true_when_both_features_present():
    cert = _build_cert(
        [(
            TLSFeature(
                features=[
                    TLSFeatureType.status_request,
                    TLSFeatureType.status_request_v2,
                ]
            ),
            False,
        )]
    )
    assert has_must_staple(cert) is True
