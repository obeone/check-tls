import datetime
import threading
import socket
import ssl
import tempfile
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from check_tls.tls_checker import fetch_leaf_certificate_and_conn_info, analyze_certificates


def generate_self_signed_cert(common_name, san_list=None, not_before=None, not_after=None):
    san_list = san_list or []
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.datetime.utcnow()
    not_before = not_before or (now - datetime.timedelta(days=1))
    not_after = not_after or (now + datetime.timedelta(days=1))
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in san_list]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    cert = builder.sign(key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_file = tempfile.NamedTemporaryFile(delete=False)
    key_file = tempfile.NamedTemporaryFile(delete=False)
    cert_file.write(cert_pem)
    cert_file.close()
    key_file.write(key_pem)
    key_file.close()
    return cert, cert_file.name, key_file.name


def generate_ca_cert(common_name="Test CA"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    cert = builder.sign(key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_file = tempfile.NamedTemporaryFile(delete=False)
    cert_file.write(cert_pem)
    cert_file.close()
    return cert, key, cert_file.name


def generate_cert_signed_by_ca(ca_cert, ca_key, common_name, san_list=None, not_before=None, not_after=None):
    san_list = san_list or []
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.datetime.utcnow()
    not_before = not_before or (now - datetime.timedelta(days=1))
    not_after = not_after or (now + datetime.timedelta(days=1))
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in san_list]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    cert = builder.sign(ca_key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_file = tempfile.NamedTemporaryFile(delete=False)
    key_file = tempfile.NamedTemporaryFile(delete=False)
    cert_file.write(cert_pem)
    cert_file.close()
    key_file.write(key_pem)
    key_file.close()
    return cert, cert_file.name, key_file.name


def start_test_server(cert_path, key_path):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    port = sock.getsockname()[1]
    stop_event = threading.Event()

    def run():
        while not stop_event.is_set():
            try:
                client, _ = sock.accept()
            except OSError:
                break
            try:
                with context.wrap_socket(client, server_side=True) as ssock:
                    try:
                        ssock.recv(1)
                    except Exception:
                        pass
            except Exception:
                pass
            finally:
                try:
                    client.close()
                except Exception:
                    pass
        sock.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    def stop():
        stop_event.set()
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
        except Exception:
            pass
        thread.join()
        os.unlink(cert_path)
        os.unlink(key_path)

    return port, stop


def test_fetch_leaf_certificate_host_mismatch_provides_details():
    cert, cert_path, key_path = generate_self_signed_cert(
        "example.com", ["example.com"],
    )
    port, stop_server = start_test_server(cert_path, key_path)
    try:
        fetched_cert, conn_info = fetch_leaf_certificate_and_conn_info(
            "localhost", port=port, insecure=True
        )
        assert fetched_cert is not None
        err = conn_info["error"] or ""
        assert "Hostname mismatch" in err
        assert "example.com" in err
        assert cert.not_valid_before_utc.isoformat() in err
        assert cert.not_valid_after_utc.isoformat() in err
    finally:
        stop_server()


def test_fetch_leaf_certificate_expired_cert_includes_details(monkeypatch):
    ca_cert, ca_key, ca_path = generate_ca_cert()
    past = datetime.datetime.utcnow() - datetime.timedelta(days=2)
    cert, cert_path, key_path = generate_cert_signed_by_ca(
        ca_cert,
        ca_key,
        "localhost",
        ["localhost"],
        not_before=past - datetime.timedelta(days=1),
        not_after=past,
    )
    port, stop_server = start_test_server(cert_path, key_path)

    orig = ssl.create_default_context

    def create_ctx(*args, **kwargs):
        ctx = orig(*args, **kwargs)
        ctx.load_verify_locations(cafile=ca_path)
        return ctx

    monkeypatch.setattr(ssl, "create_default_context", create_ctx)
    try:
        fetched_cert, conn_info = fetch_leaf_certificate_and_conn_info(
            "localhost", port=port, insecure=False
        )
        assert fetched_cert is not None
        err = conn_info["error"] or ""
        assert "SSL certificate verification failed" in err
        assert "localhost" in err
        assert cert.not_valid_before_utc.isoformat() in err
        assert cert.not_valid_after_utc.isoformat() in err
    finally:
        stop_server()
        os.unlink(ca_path)


def base_analyze(domain, port, insecure):
    return analyze_certificates(
        domain,
        port=port,
        mode="leaf",
        insecure=insecure,
        skip_transparency=True,
        perform_crl_check=False,
        perform_ocsp_check=False,
        perform_caa_check=False,
    )


def test_analyze_certificates_host_mismatch_propagates_error():
    cert, cert_path, key_path = generate_self_signed_cert(
        "example.com", ["example.com"],
    )
    port, stop_server = start_test_server(cert_path, key_path)
    try:
        result = base_analyze("localhost", port, insecure=True)
        err = result["connection_health"]["error"] or ""
        assert "Hostname mismatch" in err
        assert "example.com" in err
        assert cert.not_valid_before_utc.isoformat() in err
        assert cert.not_valid_after_utc.isoformat() in err
    finally:
        stop_server()


def test_analyze_certificates_expired_certificate_propagates_error(monkeypatch):
    ca_cert, ca_key, ca_path = generate_ca_cert()
    past = datetime.datetime.utcnow() - datetime.timedelta(days=2)
    cert, cert_path, key_path = generate_cert_signed_by_ca(
        ca_cert,
        ca_key,
        "localhost",
        ["localhost"],
        not_before=past - datetime.timedelta(days=1),
        not_after=past,
    )
    port, stop_server = start_test_server(cert_path, key_path)

    orig = ssl.create_default_context

    def create_ctx(*args, **kwargs):
        ctx = orig(*args, **kwargs)
        ctx.load_verify_locations(cafile=ca_path)
        return ctx

    monkeypatch.setattr(ssl, "create_default_context", create_ctx)
    try:
        result = base_analyze("localhost", port, insecure=False)
        err = result["connection_health"]["error"] or ""
        assert "SSL certificate verification failed" in err
        assert cert.not_valid_before_utc.isoformat() in err
        assert cert.not_valid_after_utc.isoformat() in err
        val_err = result["validation"]["error"] or ""
        assert "certificate has expired" in val_err.lower()
    finally:
        stop_server()
        os.unlink(ca_path)


def test_analyze_certificates_self_signed_chain_validation_error():
    cert, cert_path, key_path = generate_self_signed_cert(
        "localhost", ["localhost"],
    )
    port, stop_server = start_test_server(cert_path, key_path)
    try:
        result = base_analyze("localhost", port, insecure=True)
        assert result["connection_health"]["error"] is None
        val_err = result["validation"]["error"] or ""
        assert "self-signed" in val_err.lower()
    finally:
        stop_server()
