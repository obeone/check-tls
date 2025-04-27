# Flask server and web interface
import logging
import argparse
from flask import Flask, render_template_string, request, jsonify, current_app
from check_tls.tls_checker import analyze_certificates
from markupsafe import Markup

# HTML template for the web interface
def get_tooltip(text):
    return Markup(f"<span data-bs-toggle='tooltip' data-bs-placement='top' title='{text}'>🛈</span>")

HTML_TEMPLATE = """
<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>
<style>
    /* Default Light Mode */
    :root {
        --bg-color: #f8f9fa; --text-color: #212529; --card-bg: #ffffff;
        --card-border: rgba(0, 0, 0, 0.175); --table-header-bg: #e9ecef;
        --table-border: #dee2e6; --input-bg: #ffffff; --input-border: #ced4da;
        --input-text: #495057; --muted-text: #6c757d; --link-color: #0d6efd;
        --shadow-color: rgba(0, 0, 0, 0.1); --success-text: #198754;
        --warning-text: #ffc107; --danger-text: #dc3545; --secondary-text: #6c757d;
        --info-text: #0dcaf0; /* For info like 'No CDP' */
        --info-badge-bg: #0dcaf0; --secondary-badge-bg: #6c757d;
        --success-badge-bg: #198754; --warning-badge-bg: #ffc107;
        --danger-badge-bg: #dc3545; --info-badge-text: black; /* Text color for info badge */
        --alert-danger-bg: #f8d7da; --alert-danger-border: #f5c6cb; --alert-danger-text: #842029;
        --alert-warning-bg: #fff3cd; --alert-warning-border: #ffecb5; --alert-warning-text: #664d03;
        --form-check-input-bg: #ffffff; --form-check-input-border: rgba(0, 0, 0, 0.25);
        --form-check-input-checked-bg: #0d6efd; --form-check-input-checked-border: #0d6efd;
        --form-check-label-color: var(--text-color);
    }
    body { padding-top: 20px; background-color: var(--bg-color); color: var(--text-color); transition: background-color 0.3s, color 0.3s; }
    .container { max-width: 1140px; }
    .card { background-color: var(--card-bg); border: 1px solid var(--card-border); box-shadow: 0 0.125rem 0.25rem var(--shadow-color); margin-bottom: 1.5rem; }
    .card-header { background-color: transparent; border-bottom: 1px solid var(--card-border); padding: 0.75rem 1.25rem; display: flex; justify-content: space-between; align-items: center; }
    .card-header strong { font-size: 1.2em; }
    .card-body { padding: 1.25rem; }
    .table { border-color: var(--table-border); margin-bottom: 1rem; }
    .table th { width: 150px; background-color: var(--table-header-bg); white-space: nowrap; color: var(--text-color); padding: 0.5rem; vertical-align: top; }
    .table td { color: var(--text-color); padding: 0.5rem; vertical-align: top; word-break: break-word; }
    .table-sm > :not(caption) > * > * { padding: 0.25rem 0.25rem; }
    .table-bordered { border: 1px solid var(--table-border); }
    .table-bordered th, .table-bordered td { border: 1px solid var(--table-border); }
    .badge { font-size: 0.9em; padding: 0.4em 0.6em;}
    .bg-success { background-color: var(--success-badge-bg) !important; color: white; }
    .bg-warning { background-color: var(--warning-badge-bg) !important; color: black; }
    .bg-danger { background-color: var(--danger-badge-bg) !important; color: white; }
    .bg-secondary { background-color: var(--secondary-badge-bg) !important; color: white; }
    .bg-info { background-color: var(--info-badge-bg) !important; color: var(--info-badge-text); }
    .fingerprint { font-family: monospace; font-size: 0.85em; word-break: break-all; }
    .text-danger { color: var(--danger-text) !important; }
    .text-warning { color: var(--warning-text) !important; }
    .text-success { color: var(--success-text) !important; }
    .text-muted { color: var(--muted-text) !important; }
    .text-secondary { color: var(--secondary-text) !important; }
    .text-info { color: var(--info-text) !important; }
    .section-title { border-bottom: 1px solid var(--table-border); padding-bottom: 5px; margin-bottom: 15px; margin-top: 1.5rem; font-weight: bold; }
    .card-body > div + div { margin-top: 1.5rem; }
    .cert-error { background-color: #f8d7da; border-color: #f5c6cb; color: #721c24; padding: 0.5rem; margin-top: 0.5rem; border-radius: .25rem;}
    .weak-crypto { font-weight: bold; color: var(--danger-text) !important; }
    .form-control { background-color: var(--input-bg); border: 1px solid var(--input-border); color: var(--input-text); }
    .form-control:focus { background-color: var(--input-bg); color: var(--input-text); border-color: #86b7fe; box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25); }
    .form-label { color: var(--text-color); }
    .form-check-label { color: var(--form-check-label-color); }
    .form-check-input { background-color: var(--form-check-input-bg); border: 1px solid var(--form-check-input-border); }
    .form-check-input:checked { background-color: var(--form-check-input-checked-bg); border-color: var(--form-check-input-checked-border); }
    .form-check-input:focus { border-color: #86b7fe; box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25); }
    .form-check-input[type=checkbox] { border-radius: .25em; }
    .bg-warning { color: #222 !important; }
    .cert-error { background-color: #5e2129; border-color: #a0414b; color: #ffb3b8; }
    .table th, .table td {
        background-color: var(--card-bg) !important;
        color: var(--text-color) !important;
        border-color: var(--table-border) !important;
    }
    body { background-color: var(--bg-color) !important; color: var(--text-color) !important; }
    .card, .shadow-sm { background-color: var(--card-bg) !important; color: var(--text-color) !important; }
    footer small { color: var(--muted-text); }
    a { color: var(--link-color); }

    @media (prefers-color-scheme: dark) {
        :root {
            --bg-color: #181a1b; --text-color: #f4f4f4; --card-bg: #23272b;
            --card-border: #33363a;
            --table-header-bg: #292b2d;
            --table-border: #44474a; --input-bg: #23272b; --input-border: #666a6e;
            --input-text: #f4f4f4; --muted-text: #b0b3b8; --link-color: #7dbcff;
            --shadow-color: rgba(0, 0, 0, 0.4); --success-text: #5cf2b2;
            --warning-text: #ffe066; --danger-text: #ff7b72; --secondary-text: #b0b3b8;
            --info-text: #7dbcff;
            --info-badge-bg: #206bc4; --secondary-badge-bg: #5a6268;
            --success-badge-bg: #2ecc71; --warning-badge-bg: #ffe066;
            --danger-badge-bg: #ff4c51; --info-badge-text: #23272b;
            --alert-danger-bg: #3b2326; --alert-danger-border: #a0414b; --alert-danger-text: #ffb3b8;
            --alert-warning-bg: #665c03; --alert-warning-border: #c2a700; --alert-warning-text: #fffbe3;
            --form-check-input-bg: #292b2d; --form-check-input-border: #666a6e;
            --form-check-input-checked-bg: #0d6efd; --form-check-input-checked-border: #0d6efd;
            --form-check-label-color: var(--text-color);
        }
        .form-control, .form-select {
            background-color: var(--input-bg) !important;
            color: var(--input-text) !important;
            border-color: var(--input-border) !important;
        }
        .form-control::placeholder { color: #b0b3b8; }
        .form-select { background-color: var(--input-bg); border-color: var(--input-border); color: var(--input-text); }
        .form-check-input:focus { border-color: #86b7fe; box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25); }
        .form-check-input[type=checkbox] { border-radius: .25em; }
        .bg-warning { color: #222 !important; }
        .cert-error { background-color: #5e2129; border-color: #a0414b; color: #ffb3b8; }
        .table th, .table td {
            background-color: var(--card-bg) !important;
            color: var(--text-color) !important;
            border-color: var(--table-border) !important;
        }
        body { background-color: var(--bg-color) !important; color: var(--text-color) !important; }
        .card, .shadow-sm { background-color: var(--card-bg) !important; color: var(--text-color) !important; }
    }
    .tooltip-th {
        border-bottom: 1px dashed #888;
        cursor: help;
        text-decoration: none;
        position: relative;
    }
    .tooltip-th[data-tooltip]:hover:after, .tooltip-th[data-tooltip]:focus:after {
        content: attr(data-tooltip);
        position: absolute;
        left: 0;
        top: 120%;
        background: #222;
        color: #fff;
        padding: 6px 12px;
        border-radius: 4px;
        font-size: 0.75em;
        line-height: 1.4;
        white-space: pre-line;
        z-index: 10;
        opacity: 1;
        pointer-events: auto;
        transition: none;
        min-width: 220px;
        max-width: 350px;
        box-shadow: 0 2px 12px rgba(0,0,0,0.18);
    }
    .tooltip-th[data-tooltip]:after {
        opacity: 0;
        pointer-events: none;
        transition: opacity 0s;
    }
    .tooltip-th[data-tooltip]:hover:after, .tooltip-th[data-tooltip]:focus:after {
        opacity: 1;
        pointer-events: auto;
        transition-delay: 0s;
    }
</style>
<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>
<title>TLS Analysis</title>
</head>
<body>
<div class='container'>
<h1 class='mb-4 text-center'>🔒 TLS Certificate & Connection Analyzer</h1>
<form method='post' class='mb-5 p-4 border rounded shadow-sm' style='background-color: var(--card-bg);'>
<div class='mb-3'>
<label for='domains' class='form-label'>Domains to analyze (space or comma separated):</label>
<input type='text' class='form-control form-control-lg' id='domains' name='domains' placeholder='e.g. example.com test.org google.com' required>
</div>
<div class='row'>
    <div class='col-md-4 mb-3'>
        <div class='form-check'>
        <input class='form-check-input' type='checkbox' id='insecure' name='insecure' value='true' {% if insecure_checked %}checked{% endif %}>
        <label class='form-check-label' for='insecure'> Ignore SSL errors</label>
        </div>
    </div>
    <div class='col-md-4 mb-3'>
        <div class='form-check'>
        <input class='form-check-input' type='checkbox' id='no_transparency' name='no_transparency' value='true' {% if no_transparency_checked %}checked{% endif %}>
        <label class='form-check-label' for='no_transparency'> Skip Transparency Check</label>
        </div>
    </div>
    <div class='col-md-4 mb-3'>
        <div class='form-check'>
        <input class='form-check-input' type='checkbox' id='no_crl_check' name='no_crl_check' value='true' {% if no_crl_check_checked %}checked{% endif %}>
        <label class='form-check-label' for='no_crl_check'> Disable CRL Check</label>
        </div>
    </div>
</div>
<button type='submit' class='btn btn-primary w-100 btn-lg'>Analyze</button>
</form>

{% if results %}
{% for result in results %}
<div class='card mb-4 shadow-sm'>
<div class='card-header'>
<strong>{{ result.domain }}</strong>
{% set status = result.status | default('failed') %}
{% if status == 'completed' %}<span class='badge bg-success'>COMPLETED</span>
{% elif status == 'completed_with_errors' %}<span class='badge bg-warning'>COMPLETED WITH ERRORS</span>
{% else %}<span class='badge bg-danger'>FAILED</span>{% endif %}
</div>
<div class='card-body'>
    {% if result.error_message %}<div class='alert alert-danger'><strong>Status:</strong> {{ result.error_message }}</div>{% endif %}
    <p class='text-muted'><small>Analysis Time: {{ result.analysis_timestamp | default('N/A') }}</small></p>

    {# Validation Section #}
    <div> <h5 class='section-title'>Validation {{ get_tooltip('Whether the certificate is trusted by the system trust store. This is a critical check as it determines if the certificate is considered valid by the client.') }}</h5>
        {% set val = result.validation | default({}) %} {% set val_status = val.system_trust_store %}
        {% if val_status is sameas true %}<span class='badge bg-success'>✔️ Valid (System Trust)</span>
        {% elif val_status is sameas false %}<span class='badge bg-danger'>❌ Invalid (System Trust)</span> {% if val.error %}<small class='text-muted ps-2'>({{ val.error }})</small>{% endif %}
        {% elif val.error %}<span class='badge bg-danger'>❌ Error</span> <small class='text-muted ps-2'>({{ val.error }})</small>
        {% else %}<span class='badge bg-secondary'>N/A / Pending</span> {% endif %}
    </div>

    {# Leaf Certificate Summary Section #}
    {% set certs_list = result.certificates | default([]) %}
    {% set leaf_cert = certs_list[0] if certs_list and 'error' not in certs_list[0] else none %}
    {% if leaf_cert %}
    <div> <h5 class='section-title'>Leaf Certificate Summary {{ get_tooltip('Summary of the leaf (end-entity) certificate.') }}</h5>
        <table class='table table-sm table-bordered'>
             <tr><th class="tooltip-th" data-tooltip="The primary domain name (CN) for which this certificate was issued. Browsers match this against the requested domain.">Common Name</th><td>{{ leaf_cert.common_name | default('N/A') }}</td></tr>
             <tr><th class="tooltip-th" data-tooltip="The exact date and time when this certificate will expire. After this point, browsers and clients will reject it as invalid.">Expires</th><td>
                 {% set days_leaf = leaf_cert.days_remaining %}
                 {{ (leaf_cert.not_after | replace("T", " ") | replace("Z", "") | replace("+00:00", ""))[:19] | default('N/A') }}
                 {% if days_leaf is not none %}<span class='{% if days_leaf < 30 %}text-danger{% elif days_leaf < 90 %}text-warning{% else %}text-success{% endif %} fw-bold'> ({{ days_leaf }} days)</span>
                 {% else %}<span class='text-secondary'>(Expiry N/A)</span> {% endif %}
             </td></tr>
             <tr><th class="tooltip-th" data-tooltip="Subject Alternative Names (SANs): all additional domains and subdomains this certificate is valid for, in addition to the Common Name.">SANs</th><td>{{ leaf_cert.san | join(", ") | default('None') }}</td></tr>
             <tr><th class="tooltip-th" data-tooltip="The organization or Certificate Authority (CA) that issued and signed this certificate.">Issuer</th><td>{{ leaf_cert.issuer | default('N/A') }}</td></tr>
        </table>
    </div>
    {% endif %}

    {# Connection Health Section #}
    <div> <h5 class='section-title'>Connection Health {{ get_tooltip('TLS version, cipher, and protocol health of the connection.') }}</h5>
        {% set conn = result.connection_health | default({}) %}
        {% if not conn.checked %}<span class='badge bg-warning'>Not Checked / Failed</span> {% if conn.error %}<small class='text-muted ps-2'>({{ conn.error }})</small>{% endif %}
        {% else %}
        <table class='table table-sm table-bordered'>
            <tr><th class="tooltip-th" data-tooltip="The negotiated TLS protocol version used for this connection (e.g., TLS 1.3). Higher versions are generally more secure.">TLS Version</th><td>{{ conn.tls_version | default('N/A') }}</td></tr>
            <tr><th class="tooltip-th" data-tooltip="Indicates whether the server supports the latest TLS 1.3 protocol, which provides improved security and performance.">TLS 1.3 Support</th><td>
                {% set tls13_s = conn.supports_tls13 %}
                {% if tls13_s is sameas true %}<span class='text-success'>✔️ Yes</span>
                {% elif tls13_s is sameas false %}<span class='text-danger'>❌ No</span>
                {% else %}<span class='text-secondary'>N/A</span>{% endif %}
            </td></tr>
            <tr><th class="tooltip-th" data-tooltip="The specific cryptographic algorithms used to secure the connection, including key exchange, encryption, and authentication.">Cipher Suite</th><td>{{ conn.cipher_suite | default('N/A') }}</td></tr>
        </table>
        {% if conn.error %}<div class='alert alert-danger mt-2'><small>Connection Error: {{ conn.error }}</small></div>{% endif %}
        {% endif %}
    </div>

    {# CRL Check Section #}
    <div><h5 class='section-title'>CRL Check (Leaf Certificate) {{ get_tooltip('Checks if the certificate is revoked using CRL.') }}</h5>
        {% set crl_check_data = result.crl_check | default({}) %}
        {% if not crl_check_data.checked %}
             <span class='badge bg-secondary'>Skipped</span>
        {% else %}
            {% set crl_status = crl_check_data.leaf_status | default('error') %}
            {% set crl_details = crl_check_data.details | default({}) %}
            {% set crl_reason = crl_details.reason if crl_details is mapping else 'No details' %}
            {% set crl_uri = crl_details.checked_uri if crl_details is mapping else None %}

            {% if crl_status == "good" %} <span class='badge bg-success'>✔️ Good</span>
            {% elif crl_status == "revoked" %} <span class='badge bg-danger'>❌ REVOKED</span>
            {% elif crl_status == "crl_expired" %} <span class='badge bg-warning'>⚠️ CRL Expired</span>
            {% elif crl_status == "unreachable" %} <span class='badge bg-warning'>⚠️ Unreachable</span>
            {% elif crl_status == "parse_error" %} <span class='badge bg-danger'>❌ Parse Error</span>
            {% elif crl_status == "no_cdp" %} <span class='badge bg-info'>ℹ️ No CDP</span>
            {% elif crl_status == "no_http_cdp" %} <span class='badge bg-info'>ℹ️ No HTTP CDP</span>
            {% elif crl_status == "error" %} <span class='badge bg-danger'>❌ Error</span>
            {% else %} <span class='badge bg-secondary'>❓ Unknown</span>
            {% endif %}
            <p class='text-muted mt-1'><small>
                {{ crl_reason }}
                {% if crl_uri %} <br>Checked URI: {{ crl_uri }} {% endif %}
            </small></p>
        {% endif %}
    </div>

    {# Certificate Chain Details Section #}
     <div> <h5 class='section-title'>Certificate Chain Details {{ get_tooltip('Details of each certificate in the chain.') }}</h5>
        {% if not certs_list and result.status != 'failed' %}<div class='alert alert-warning'>No certificates were processed successfully.</div>
        {% elif not certs_list and result.status == 'failed' %}<div class='alert alert-danger'>Certificate fetching or analysis failed.</div>
        {% endif %}
        {% for cert in certs_list %}
            <h6 class="mt-3">Certificate #{{ loop.index }}
                {% if cert.error %} <span class='text-danger'>(Error Analyzing)</span>
                {% elif cert.chain_index == 0 %} (Leaf)
                {% elif cert.is_ca %} (CA/Intermediate)
                {% else %} (Intermediate) {% endif %}
             </h6>
            {% if cert.error %}<div class='cert-error'><strong>Error:</strong> {{ cert.error }}</div>
            {% else %}
            <table class='table table-sm table-bordered mb-3'>
                <tr><th class="tooltip-th" data-tooltip="The distinguished name (DN) of the entity this certificate is issued to, including organization, location, and CN.">Subject</th><td>{{ cert.subject | default('N/A') }}</td></tr>
                <tr><th class="tooltip-th" data-tooltip="The organization or Certificate Authority (CA) that issued and signed this certificate.">Issuer</th><td>{{ cert.issuer | default('N/A') }}</td></tr>
                <tr><th class="tooltip-th" data-tooltip="The primary domain name (CN) for which this certificate was issued. Browsers match this against the requested domain.">Common Name</th><td>{{ cert.common_name | default('N/A') }}</td></tr>
                <tr><th class="tooltip-th" data-tooltip="A unique identifier assigned to this certificate by the issuer. Useful for revocation and auditing.">Serial</th><td>{{ cert.serial_number | default('N/A') }}</td></tr>
                <tr><th class="tooltip-th" data-tooltip="The X.509 version of this certificate. Modern certificates use version 3.">Version</th><td>{{ cert.version | default('N/A') }}</td></tr>
                <tr><th class="tooltip-th" data-tooltip="The period during which this certificate is considered valid, from 'not before' to 'not after' dates.">Validity</th><td>
                    {{ (cert.not_before | replace("T", " ") | replace("Z", "") | replace("+00:00", ""))[:19] | default('N/A') }} →
                    {{ (cert.not_after | replace("T", " ") | replace("Z", "") | replace("+00:00", ""))[:19] | default('N/A') }} <br>
                    {% set days = cert.days_remaining %}
                    {% if days is not none %}<span class='{% if days < 30 %}text-danger{% elif days < 90 %}text-warning{% else %}text-success{% endif %} fw-bold'> ({{ days }} days remaining)</span>
                    {% else %}<span class='text-secondary'>(Expiry N/A)</span> {% endif %}
                </td></tr>
                <tr><th class="tooltip-th" data-tooltip="Details about the public key in this certificate, including algorithm (e.g., RSA, ECDSA) and key size in bits. Weak keys are insecure.">Key</th><td>
                    {% set k_algo = cert.public_key_algorithm | default('N/A') %} {% set k_size = cert.public_key_size_bits %} {{ k_algo }}
                    {% if k_size %}
                        {% set weak_key = (k_algo == 'RSA' and k_size < 2048) or ('ECDSA' in k_algo and k_size < 256) or (k_algo == 'DSA' and k_size < 2048) %}
                        (<span class='{% if weak_key %}weak-crypto{% endif %}'>{{ k_size }} bits</span>){% if weak_key %}<span class='weak-crypto ps-1'>(Weak)</span>{% endif %}
                    {% endif %}
                </td></tr>
                <tr><th class="tooltip-th" data-tooltip="The algorithm used by the issuer to sign this certificate. Weak signature algorithms (like SHA1/MD5) are insecure.">Signature Algo</th><td>
                     {% set sig_algo = cert.signature_algorithm | default('N/A') %} {% set weak_hash = "sha1" in sig_algo.lower() or "md5" in sig_algo.lower() %}
                     <span class='{% if weak_hash %}weak-crypto{% endif %}'>{{ sig_algo }}</span>{% if weak_hash %}<span class='weak-crypto ps-1'>(Weak)</span>{% endif %}
                </td></tr>
                 <tr><th class="tooltip-th" data-tooltip="The SHA-256 fingerprint is a unique hash of the certificate. It can be used to verify or pin a certificate.">SHA256 FP</th><td class='fingerprint'>{{ cert.sha256_fingerprint | default('N/A') }}</td></tr>
                <tr><th class="tooltip-th" data-tooltip="A high-level classification of the certificate's intended usage, such as server authentication or CA root.">Profile</th><td>{{ cert.profile | default('N/A') }}</td></tr>
                <tr><th class="tooltip-th" data-tooltip="Whether this certificate can act as a Certificate Authority (CA) and issue other certificates. PathLen shows CA depth.">Is CA</th><td> {% if cert.is_ca is sameas true %}Yes{% elif cert.is_ca is sameas false %}No{% else %}N/A{% endif %} {% if cert.is_ca %} (PathLen: {{ cert.path_length_constraint if cert.path_length_constraint is not none else 'None' }}) {% endif %} </td></tr>
                <tr><th class="tooltip-th" data-tooltip="Whether this certificate contains embedded Signed Certificate Timestamps (SCTs) for Certificate Transparency.">Embedded SCTs</th><td>
                    {% set sct_s = cert.has_scts %}
                    {% if sct_s is sameas true %}<span class='text-success'>✔️ Yes</span>
                    {% elif sct_s is sameas false %}<span class='text-warning'>❌ No</span>
                    {% else %}<span class='text-secondary'>N/A</span>{% endif %}
                </td></tr>
            </table>
            {% endif %}
        {% endfor %}
    </div>

    {# Certificate Transparency Section #}
    <div> <h5 class='section-title'>Certificate Transparency (crt.sh) {{ get_tooltip('Checks for issued certificates for this and parent domains in public CT logs.') }}</h5>
         {% set trans = result.transparency | default({}) %}
         {% if not trans.checked %}<span class='badge bg-secondary'>Skipped</span>
         {% elif trans.errors %}
            <span class='badge bg-danger'>Error</span>
            <ul>
            {% for d, err in trans.errors.items() %}
                <li><strong>{{ d }}</strong>: {{ err }} {% if trans.crtsh_report_links and trans.crtsh_report_links[d] %}<a href="{{ trans.crtsh_report_links[d] }}" target="_blank" rel="noopener" class="ms-2">[View on crt.sh]</a>{% endif %}</li>
            {% endfor %}
            </ul>
         {% else %}
              <ul>
              {% for d, records in trans.details.items() %}
                  <li><strong>{{ d }}</strong>:
                      {% if records is none %} <span class='badge bg-danger'>Error</span>
                      {% else %} <span class='badge bg-info'>{{ records|length }} records</span>
                      {% endif %}
                      {% if trans.crtsh_report_links and trans.crtsh_report_links[d] %}<a href="{{ trans.crtsh_report_links[d] }}" target="_blank" rel="noopener" class="ms-2">[View on crt.sh]</a>{% endif %}
                  </li>
              {% endfor %}
              </ul>
              <span class='ps-2'>Total records found:</span> <span class='badge bg-info'>{{ trans.crtsh_records_found }}</span>
         {% endif %}
    </div>

</div> {# End Card Body #}
</div> {# End Card #}
{% endfor %}
{% endif %}
<footer class='text-center text-muted mt-5 mb-3'> <small><a href="https://github.com/obeone/check-tls" target="_blank" rel="noopener">TLS Check</a></small></footer>
</div>
</body>
</html>
"""

def run_server(args):
    """
    Run the Flask web server for interactive TLS analysis.
    """
    app = Flask(__name__)
    app.config['SCRIPT_ARGS'] = args

    @app.route('/', methods=['GET', 'POST'])
    def index():
        script_args = current_app.config['SCRIPT_ARGS']
        results = None
        insecure_checked = script_args.insecure
        no_transparency_checked = script_args.no_transparency
        no_crl_check_checked = script_args.no_crl_check

        if request.method == 'POST':
            raw_domains = request.form.get('domains', '')
            domains = [d.strip() for d in raw_domains.replace(',', ' ').split() if d.strip()]
            insecure_flag = request.form.get('insecure') == 'true'
            no_transparency_flag = request.form.get('no_transparency') == 'true'
            no_crl_check_flag = request.form.get('no_crl_check') == 'true'
            results = [analyze_certificates(domain, insecure=insecure_flag, skip_transparency=no_transparency_flag, perform_crl_check=not no_crl_check_flag) for domain in domains]
        accept_header = request.headers.get('Accept', '')
        if accept_header == 'application/json' and results is not None:
            response = jsonify(results)
            response.mimetype = 'application/json; charset=utf-8'
            return response
        else:
            return render_template_string(HTML_TEMPLATE, results=results,
                                          insecure_checked=insecure_checked,
                                          no_transparency_checked=no_transparency_checked,
                                          no_crl_check_checked=no_crl_check_checked,
                                          get_tooltip=get_tooltip)

    @app.route('/api/analyze', methods=['POST'])
    def api_analyze():
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
        data = request.get_json()
        domains = data.get('domains')
        if not domains or not isinstance(domains, list):
            return jsonify({'error': 'JSON body must contain a list of domains under "domains"'}), 400
        insecure_flag = bool(data.get('insecure', False))
        no_transparency_flag = bool(data.get('no_transparency', False))
        no_crl_check_flag = bool(data.get('no_crl_check', False))
        results = [analyze_certificates(domain,
                                        insecure=insecure_flag,
                                        skip_transparency=no_transparency_flag,
                                        perform_crl_check=not no_crl_check_flag)
                   for domain in domains]
        return jsonify(results)

    logging.info(f"Starting Flask server on http://0.0.0.0:{args.port}")
    try:
        app.run(host='0.0.0.0', port=args.port, debug=False)
    except Exception as e:
        logging.error(f"Failed to start Flask server: {e}")


def get_flask_app():
    """Function to return the app instance, needed for WSGI servers like waitress."""
    app = Flask(__name__)
    # Add similar logic as run_server for WSGI compatibility
    return app
