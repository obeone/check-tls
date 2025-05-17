// static/js/app.js

document.addEventListener('DOMContentLoaded', function() {
  const form = document.getElementById('analyze-form');
  const progressBar = document.getElementById('progress-bar');
  const resultsDiv = document.getElementById('results');
  const summaryTableWrapper = document.getElementById('summary-table-wrapper');
  const summaryTableBody = document.querySelector('#summary-table tbody');

  // Helper for status badge/icon
  function statusBadge(status) {
    if (status === 'completed')   return '<span class="badge badge-ok">✔️ Completed</span>';
    if (status === 'completed_with_errors') return '<span class="badge badge-warning">⚠️ Completed w/ Errors</span>';
    return '<span class="badge badge-expired">❌ Failed</span>';
  }
  function expiryBadge(days) {
    if (days < 0) return '<span class="badge badge-expired">Expired</span>';
    if (days < 30) return '<span class="badge badge-expired">' + days + 'd</span>';
    if (days < 90) return '<span class="badge badge-warning">' + days + 'd</span>';
    return '<span class="badge badge-ok">' + days + 'd</span>';
  }
  function tls13Badge(support) {
    if (support === true) return '<span class="badge badge-ok">1.3</span>';
    if (support === false) return '<span class="badge badge-expired">No</span>';
    return '<span class="badge badge-warning">?</span>';
  }
  function crlBadge(crl) {
    if (!crl || !crl.checked) return '<span class="badge bg-secondary">N/A</span>';
    if (crl.leaf_status === "good") return '<span class="badge badge-ok">Good</span>';
    if (crl.leaf_status === "revoked") return '<span class="badge badge-expired">Revoked</span>';
    if (crl.leaf_status === "crl_expired") return '<span class="badge badge-warning">CRL Expired</span>';
    if (crl.leaf_status === "unreachable") return '<span class="badge badge-warning">Unreachable</span>';
    if (crl.leaf_status === "parse_error") return '<span class="badge badge-expired">Parse Error</span>';
    return '<span class="badge bg-secondary">?</span>';
  }

  // Populate Summary Table
  function renderSummary(results) {
    summaryTableBody.innerHTML = '';
    if (!Array.isArray(results)) results = [results];
    results.forEach((r, i) => {
      const leaf = (r.certificates || []).find(c => c.chain_index === 0 && !c.error) || {};
      summaryTableBody.innerHTML += `
        <tr>
          <td><b>${r.domain || '-'}</b></td>
          <td>${statusBadge(r.status)}</td>
          <td>${leaf.common_name || '-'}</td>
          <td>${leaf.not_after ? (leaf.not_after.substring(0, 10)) : '-' }<br>
              ${expiryBadge(leaf.days_remaining ?? 0)}
          </td>
          <td>${leaf.issuer || '-'}</td>
          <td>${(r.connection_health && r.connection_health.tls_version) || '-' }
              ${tls13Badge(r.connection_health && r.connection_health.supports_tls13)}
          </td>
          <td>${crlBadge(r.crl_check)}</td>
          <td>
            <button class="btn btn-sm btn-outline-primary" data-scroll="#card-${i}">Details</button>
          </td>
        </tr>
      `;
    });
    summaryTableWrapper.style.display = results.length ? 'block' : 'none';
    // Scroll to card on click
    summaryTableBody.querySelectorAll('button[data-scroll]').forEach(btn => {
      btn.onclick = () => {
        const target = document.querySelector(btn.getAttribute('data-scroll'));
        if (target) target.scrollIntoView({behavior: 'smooth', block: 'start'});
      };
    });
  }

  // Card renderer
  function renderResult(result, idx=0) {
    const leaf = (result.certificates || []).find(c => c.chain_index === 0 && !c.error) || {};
    // Quick info
    let daysClass = leaf.days_remaining < 0 ? 'expired' : leaf.days_remaining < 30 ? 'days-remaining-critical' : leaf.days_remaining < 90 ? 'days-remaining-warning' : 'days-remaining-ok';
    let statusText = result.status === 'completed' ? 'Valid' : result.status === 'completed_with_errors' ? 'Valid (with errors)' : 'Failed';

    // Card HTML
    const card = document.createElement('div');
    card.className = 'card mb-4 shadow';
    card.id = `card-${idx}`;
    card.innerHTML = `
      <div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2">
        <div>
          <span class="fw-bold fs-5">${result.domain || '-'}</span>
          ${statusBadge(result.status)}
        </div>
        <div class="text-muted small">Analysis Time: ${result.analysis_timestamp || 'N/A'}</div>
      </div>
      <div class="card-body">
        <!-- Synthesis row -->
        <div class="row align-items-center g-3 pb-3 border-bottom mb-3">
          <div class="col-6 col-md-3">
            <span class="fw-semibold text-muted">CN:</span><br>
            <span class="fs-6">${leaf.common_name || '-'}</span>
          </div>
          <div class="col-6 col-md-3">
            <span class="fw-semibold text-muted">Expires:</span><br>
            <span class="fs-6 ${daysClass}">${leaf.not_after ? leaf.not_after.substring(0, 10) : '-'}</span>
            <span class="badge ms-2 ${daysClass}">${leaf.days_remaining ?? '?'}</span>
          </div>
          <div class="col-6 col-md-3">
            <span class="fw-semibold text-muted">Issuer:</span><br>
            <span class="fs-6">${leaf.issuer || '-'}</span>
          </div>
          <div class="col-6 col-md-3">
            <span class="fw-semibold text-muted">TLS:</span><br>
            <span class="fs-6">${(result.connection_health && result.connection_health.tls_version) || '-'}</span>
            ${tls13Badge(result.connection_health && result.connection_health.supports_tls13)}
          </div>
        </div>
        <!-- Alerts -->
        ${result.error_message ? `<div class="alert alert-danger mt-2"><b>Overall Status:</b> ${result.error_message}</div>` : ""}
        <!-- Accordion details -->
        <div class="accordion mt-4" id="accordion-${idx}">
          <div class="accordion-item">
            <h2 class="accordion-header" id="heading-details-${idx}">
              <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-details-${idx}">
                Certificate chain and details
              </button>
            </h2>
            <div id="collapse-details-${idx}" class="accordion-collapse collapse" aria-labelledby="heading-details-${idx}">
              <div class="accordion-body">
                ${renderChainTable(result)}
              </div>
            </div>
          </div>
        </div>
      </div>
    `;
    return card;
  }

  // Certificate chain details as HTML table (can be improved/extended)
  function renderChainTable(result) {
    const certs = result.certificates || [];
    if (!certs.length) return `<div class="alert alert-warning">No certificate data available.</div>`;
    return certs.map((cert, i) => `
      <h6 class="mt-3 mb-2">Certificate #${i+1} ${cert.chain_index===0 ? '(Leaf)' : (cert.is_ca ? '(CA/Intermediate)' : '(Intermediate)')}</h6>
      ${cert.error ? `<div class="alert alert-danger">${cert.error}</div>` : `
      <table class="table table-sm table-bordered mb-3">
        <tr><th>Subject</th><td>${cert.subject || '-'}</td></tr>
        <tr><th>Issuer</th><td>${cert.issuer || '-'}</td></tr>
        <tr><th>Common Name</th><td>${cert.common_name || '-'}</td></tr>
        <tr><th>Serial</th><td>${cert.serial_number || '-'}</td></tr>
        <tr><th>Validity</th><td>${cert.not_before || '-'} → ${cert.not_after || '-'}<br>
            <span class="${cert.days_remaining < 0 ? 'days-remaining-critical' : cert.days_remaining < 30 ? 'days-remaining-warning' : 'days-remaining-ok'}">${cert.days_remaining ?? '?'} days left</span>
        </td></tr>
        <tr><th>Key</th><td>${cert.public_key_algorithm || '-'} (${cert.public_key_size_bits || '?'} bits)</td></tr>
        <tr><th>Signature Algo</th><td>${cert.signature_algorithm || '-'}</td></tr>
        <tr><th>SHA256 FP</th><td><span class="fingerprint">${cert.sha256_fingerprint || '-'}</span></td></tr>
        <tr><th>Profile</th><td>${cert.profile || '-'}</td></tr>
        <tr><th>Is CA</th><td>${cert.is_ca ? 'Yes' : 'No'}</td></tr>
        <tr><th>SANs</th><td>${(cert.san || []).join(', ') || '-'}</td></tr>
      </table>
      `}
    `).join('');
  }

  // Handle form submit
  form.addEventListener('submit', function(event) {
    event.preventDefault();
    progressBar.style.display = 'block';
    progressBar.querySelector('.progress-bar').style.width = '20%';

    const formData = new FormData(form);
    const domainsString = formData.get('domains') || '';
    const domainsArray = domainsString.replace(/,/g, ' ').split(/\s+/).filter(domain => domain.trim() !== '');
    const connectPort = parseInt(formData.get('connect_port'), 10) || 443;
    const insecure = formData.get('insecure') === 'true';
    const noTransparency = formData.get('no_transparency') === 'true';
    const noCrlCheck = formData.get('no_crl_check') === 'true';

    const payload = {
      domains: domainsArray,
      connect_port: connectPort,
      insecure: insecure,
      no_transparency: noTransparency,
      no_crl_check: noCrlCheck
    };

    fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
    .then(response => {
      progressBar.querySelector('.progress-bar').style.width = '70%';
      if (!response.ok) {
        return response.text().then(text => { throw new Error(`Server error: ${response.status} ${text || response.statusText}`) });
      }
      return response.json();
    })
    .then(results => {
      progressBar.style.display = 'none';
      progressBar.querySelector('.progress-bar').style.width = '0%';
      resultsDiv.innerHTML = '';
      // Render summary and results
      renderSummary(results);
      if (Array.isArray(results)) {
        results.forEach((result, i) => resultsDiv.appendChild(renderResult(result, i)));
      } else {
        resultsDiv.appendChild(renderResult(results, 0));
      }
    })
    .catch(error => {
      progressBar.style.display = 'none';
      progressBar.querySelector('.progress-bar').style.width = '0%';
      summaryTableWrapper.style.display = 'none';
      resultsDiv.innerHTML = `<div class="alert alert-danger"><strong>Error:</strong> ${error.message || error}</div>`;
    });
  });
});
