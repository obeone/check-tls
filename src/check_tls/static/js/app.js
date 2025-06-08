// static/js/app.js

document.addEventListener('DOMContentLoaded', function() {
  const form = document.getElementById('analyze-form');
  const loadingSpinner = document.getElementById('loading-spinner');
  const resultsDiv = document.getElementById('results');
  const summaryTableWrapper = document.getElementById('summary-table-wrapper');
  const summaryTableBody = document.querySelector('#summary-table tbody');
  const themeToggle = document.getElementById('theme-toggle');

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-bs-theme', theme);
    localStorage.setItem('theme', theme);
    if (themeToggle) {
      themeToggle.textContent = theme === 'dark' ? 'Light Mode' : 'Dark Mode';
    }
  }

  const savedTheme = localStorage.getItem('theme') || document.documentElement.getAttribute('data-bs-theme') || 'dark';
  applyTheme(savedTheme);

  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const newTheme = document.documentElement.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
      applyTheme(newTheme);
    });
  }

  // Helper for status badge/icon
  function statusBadge(status) {
    if (status === 'completed')   return '<span class="badge badge-ok">✔️ Completed</span>';
    if (status === 'completed_with_errors') return '<span class="badge badge-warning">⚠️ Completed w/ Errors</span>';
    return '<span class="badge badge-expired">❌ Failed</span>';
  }
  function expiryBadge(days) {
    // Returns a badge indicating certificate expiry status based on days remaining.
    // badge-expired: Certificate has expired (days < 0)
    // badge-warning: Certificate expires soon (0 <= days < 30)
    // badge-ok: Certificate is valid for a longer period (days >= 30)
    if (days < 0) return '<span class="badge badge-expired">Expired</span>';
    if (days < 30) return '<span class="badge badge-warning">' + days + 'd</span>';
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

  function ocspBadge(ocsp) {
    if (!ocsp || !ocsp.checked) return '<span class="badge bg-secondary">N/A</span>';
    if (ocsp.status === "good") return '<span class="badge badge-ok">Good</span>';
    if (ocsp.status === "revoked") return '<span class="badge badge-expired">Revoked</span>';
    if (ocsp.status === "unknown") return '<span class="badge badge-warning">Unknown</span>';
    // Consider other statuses like 'error' or specific error messages if available in your data
    return '<span class="badge badge-expired">Error</span>'; // Default for other cases like error
  }

  function transparencyBadge(transparencyData) {
    // Updated based on Python output structure:
    // transparencyData is expected to be result.transparency
    // { checked: true/false, crtsh_records_found: number | null, errors: {...}, details: {...} }
    if (!transparencyData || typeof transparencyData.checked === 'undefined') {
        // This case should ideally not happen if API always returns the transparency object
        return '<span class="badge bg-secondary">Error?</span>';
    }
    if (!transparencyData.checked) return '<span class="badge bg-secondary">N/A (Skipped)</span>';

    if (transparencyData.errors && Object.keys(transparencyData.errors).length > 0) {
        // If there are errors for any domain part, mark as error
        return '<span class="badge badge-expired">Error</span>';
    }
    // Check if records were found. crtsh_records_found can be 0.
    if (typeof transparencyData.crtsh_records_found === 'number' && transparencyData.crtsh_records_found > 0) {
        return '<span class="badge badge-ok">Found</span>';
    }
    if (typeof transparencyData.crtsh_records_found === 'number' && transparencyData.crtsh_records_found === 0) {
        return '<span class="badge badge-warning">Not Found</span>';
    }
    // Fallback for unexpected states, e.g. checked is true but no records_found and no errors
    return '<span class="badge badge-warning">Unknown</span>';
  }

  // Populate Summary Table
  function renderSummary(results) {
    summaryTableBody.innerHTML = '';
    if (!Array.isArray(results)) results = [results];
    results.forEach((r, i) => {
      const leaf = (r.certificates || []).find(c => c.chain_index === 0 && !c.error) || {};
      // Attempt to get a crt.sh query value. Prefer SHA256 fingerprint, fallback to common name.
      const crtshQuery = leaf.sha256_fingerprint || leaf.common_name || r.domain;
      const crtshLink = crtshQuery ? `https://crt.sh/?q=${encodeURIComponent(crtshQuery)}` : '#';
      const crtshAnchor = crtshQuery ? `<a href="${crtshLink}" target="_blank" class="btn btn-sm btn-outline-info">crt.sh</a>` : '-';

      summaryTableBody.innerHTML += `
        <tr>
          <td data-bs-toggle="tooltip" data-bs-title="The domain name that was analyzed."><b>${r.domain || '-'}</b></td>
          <td data-bs-toggle="tooltip" data-bs-title="The overall status of the TLS analysis for this domain.">${statusBadge(r.status)}</td>
          <td data-bs-toggle="tooltip" data-bs-title="Common Name (CN) of the leaf certificate.">${leaf.common_name || '-'}</td>
          <td data-bs-toggle="tooltip" data-bs-title="Expiration date of the leaf certificate and days remaining.">${leaf.not_after ? (leaf.not_after.substring(0, 10)) : '-' }<br>
              ${expiryBadge(leaf.days_remaining ?? 0)}
          </td>
          <td data-bs-toggle="tooltip" data-bs-title="Issuer of the leaf certificate.">${leaf.issuer || '-'}</td>
          <td data-bs-toggle="tooltip" data-bs-title="TLS version used for the connection and TLS 1.3 support.">${(r.connection_health && r.connection_health.tls_version) || '-' }
              ${tls13Badge(r.connection_health && r.connection_health.supports_tls13)}
          </td>
          <td data-bs-toggle="tooltip" data-bs-title="Certificate Revocation List (CRL) check status for the leaf certificate.">${crlBadge(r.crl_check)}</td>
          <td data-bs-toggle="tooltip" data-bs-title="Online Certificate Status Protocol (OCSP) check status for the leaf certificate.">${ocspBadge(r.ocsp_check)}</td>
          <td data-bs-toggle="tooltip" data-bs-title="Certificate Transparency (CT) log check status.">${transparencyBadge(r.transparency)}</td>
          <td data-bs-toggle="tooltip" data-bs-title="Link to crt.sh for the certificate or domain.">${crtshAnchor}</td>
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
    const transparencyDetailsHtml = renderTransparencyDetailsTable(result.transparency, idx);
    // Quick info
    // Determine CSS class for expiry text/badge based on days remaining
    // expired: Certificate has expired (days < 0)
    // days-remaining-warning: Certificate expires soon (0 <= days < 30)
    // days-remaining-ok: Certificate is valid for a longer period (days >= 30)
    let daysClass = leaf.days_remaining < 0 ? 'expired' : leaf.days_remaining < 30 ? 'days-remaining-warning' : 'days-remaining-ok';
    let statusText = result.status === 'completed' ? 'Valid' : result.status === 'completed_with_errors' ? 'Valid (with errors)' : 'Failed';

    // Card HTML
    const card = document.createElement('div');
    card.className = 'card mb-4 shadow';
    card.id = `card-${idx}`;
    card.innerHTML = `
      <div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2">
        <div>
          <span class="fw-bold fs-5" data-bs-toggle="tooltip" data-bs-title="The domain name that was analyzed.">${result.domain || '-'}</span>
          ${statusBadge(result.status)}
        </div>
        <div class="text-muted small" data-bs-toggle="tooltip" data-bs-title="Timestamp of when the analysis was performed.">Analysis Time: ${result.analysis_timestamp || 'N/A'}</div>
      </div>
      <div class="card-body">
        <!-- Synthesis row -->
        <div class="row align-items-center g-3 pb-3 border-bottom mb-3">
          <div class="col-6 col-md-3" data-bs-toggle="tooltip" data-bs-title="Common Name (CN) of the leaf certificate.">
            <span class="fw-semibold text-muted">CN:</span><br>
            <span class="fs-6">${leaf.common_name || '-'}</span>
          </div>
          <div class="col-6 col-md-3" data-bs-toggle="tooltip" data-bs-title="Expiration date of the leaf certificate and days remaining.">
            <span class="fw-semibold text-muted">Expires:</span><br>
            <span class="fs-6 ${daysClass}">${leaf.not_after ? leaf.not_after.substring(0, 10) : '-'}</span>
            <span class="badge ms-2 ${daysClass}">${leaf.days_remaining ?? '?'}d</span>
          </div>
          <div class="col-6 col-md-3" data-bs-toggle="tooltip" data-bs-title="Issuer of the leaf certificate.">
            <span class="fw-semibold text-muted">Issuer:</span><br>
            <span class="fs-6">${leaf.issuer || '-'}</span>
          </div>
          <div class="col-6 col-md-3" data-bs-toggle="tooltip" data-bs-title="TLS version used for the connection and TLS 1.3 support.">
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
            <h2 class="accordion-header" id="heading-cert-details-${idx}">
              <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-cert-details-${idx}">
                Certificate Chain Details
              </button>
            </h2>
            <div id="collapse-cert-details-${idx}" class="accordion-collapse collapse" aria-labelledby="heading-cert-details-${idx}">
              <div class="accordion-body">
                ${renderChainTable(result)}
              </div>
            </div>
          </div>
          ${transparencyDetailsHtml}
        </div>
      </div>
    `;
    return card;
  }

  // Render Certificate Transparency details table
  function renderTransparencyDetailsTable(transparencyData, parentIdx) {
    if (!transparencyData || !transparencyData.checked) {
      return `
        <div class="accordion-item">
          <h2 class="accordion-header" id="heading-transparency-${parentIdx}">
            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-transparency-${parentIdx}">
              Certificate Transparency (CT) Log Check
            </button>
          </h2>
          <div id="collapse-transparency-${parentIdx}" class="accordion-collapse collapse" aria-labelledby="heading-transparency-${parentIdx}">
            <div class="accordion-body">
              <p class="text-muted">Certificate Transparency check was skipped.</p>
            </div>
          </div>
        </div>`;
    }

    let tableRows = '';
    if (transparencyData.details) {
      for (const domain in transparencyData.details) {
        const records = transparencyData.details[domain];
        const recordCount = Array.isArray(records) ? records.length : (records === null ? 'Error/Timeout' : '0');
        const crtshLink = transparencyData.crtsh_report_links && transparencyData.crtsh_report_links[domain]
          ? `<a href="${transparencyData.crtsh_report_links[domain]}" target="_blank" class="btn btn-sm btn-outline-info">View on crt.sh</a>`
          : '-';
        let statusBadge = '';
        if (transparencyData.errors && transparencyData.errors[domain]) {
            statusBadge = '<span class="badge bg-danger">Error</span>';
        } else if (recordCount === 'Error/Timeout') {
            statusBadge = '<span class="badge bg-warning">Timeout/Error</span>';
        } else if (recordCount > 0) {
            statusBadge = `<span class="badge bg-success">${recordCount}</span>`;
        } else {
            statusBadge = `<span class="badge bg-secondary">${recordCount}</span>`;
        }

        tableRows += `
          <tr>
            <td>${domain}</td>
            <td class="text-center">${statusBadge}</td>
            <td class="text-center">${crtshLink}</td>
          </tr>`;
      }
    }

    if (!tableRows && transparencyData.errors && Object.keys(transparencyData.errors).length > 0) {
        for (const domain in transparencyData.errors) {
             const crtshLink = transparencyData.crtsh_report_links && transparencyData.crtsh_report_links[domain]
                ? `<a href="${transparencyData.crtsh_report_links[domain]}" target="_blank" class="btn btn-sm btn-outline-info">View on crt.sh</a>`
                : '-';
            tableRows += `
              <tr>
                <td>${domain}</td>
                <td class="text-center"><span class="badge bg-danger">Error: ${transparencyData.errors[domain]}</span></td>
                <td class="text-center">${crtshLink}</td>
              </tr>`;
        }
    }


    const tableHtml = tableRows ? `
      <div class="table-responsive">
        <table class="table table-sm table-bordered table-hover">
          <thead class="table-light">
            <tr>
              <th>Queried Domain/Subdomain</th>
              <th class="text-center">Records Found</th>
              <th class="text-center">crt.sh Link</th>
            </tr>
          </thead>
          <tbody>
            ${tableRows}
          </tbody>
        </table>
      </div>` : '<p class="text-muted">No detailed transparency data available or an error occurred.</p>';

    return `
      <div class="accordion-item">
        <h2 class="accordion-header" id="heading-transparency-${parentIdx}">
          <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-transparency-${parentIdx}">
            Certificate Transparency (CT) Log Details
          </button>
        </h2>
        <div id="collapse-transparency-${parentIdx}" class="accordion-collapse collapse" aria-labelledby="heading-transparency-${parentIdx}">
          <div class="accordion-body">
            ${tableHtml}
            ${transparencyData.total_records !== undefined ? `<p class="mt-2"><strong>Total records found across all queried domains: ${transparencyData.total_records}</strong></p>` : ''}
          </div>
        </div>
      </div>`;
  }

  // Certificate chain details as HTML table (can be improved/extended)
  function renderChainTable(result) {
    // Helper function to create a table cell with a tooltip
    function tdWithTooltip(content, title) {
      return `<td data-bs-toggle="tooltip" data-bs-title="${title}">${content}</td>`;
    }

    const certs = result.certificates || [];
    if (!certs.length) return `<div class="alert alert-warning">No certificate data available.</div>`;
    return certs.map((cert, i) => `
      <h6 class="mt-3 mb-2">Certificate #${i+1} ${cert.chain_index===0 ? '(Leaf)' : (cert.is_ca ? '(CA/Intermediate)' : '(Intermediate)')}</h6>
      ${cert.error ? `<div class="alert alert-danger">${cert.error}</div>` : `
      <table class="table table-sm table-bordered mb-3">
        <tr><th>Subject</th>${tdWithTooltip(cert.subject || '-', "The distinguished name (DN) of the entity to whom the certificate is issued.")}</tr>
        <tr><th>Issuer</th>${tdWithTooltip(cert.issuer || '-', "The distinguished name (DN) of the entity that signed and issued the certificate.")}</tr>
        <tr><th>Common Name</th>${tdWithTooltip(cert.common_name || '-', "The primary common name (CN) of the certificate, typically the domain name for SSL/TLS certificates.")}</tr>
        <tr><th>Serial</th>${tdWithTooltip(cert.serial_number || '-', "A unique serial number assigned to the certificate by the issuing Certificate Authority (CA).")}</tr>
        <tr><th>Validity</th>${tdWithTooltip(`${cert.not_before || '-'} → ${cert.not_after || '-'}<br><span class="${cert.days_remaining < 0 ? 'days-remaining-critical' : cert.days_remaining < 10 ? 'days-remaining-warning' : 'days-remaining-ok'}">${cert.days_remaining ?? '?'} days left</span>`, "The period during which the certificate is considered valid, defined by 'Not Before' and 'Not After' dates.")}</tr>
        <tr><th>Key</th>${tdWithTooltip(`${cert.public_key_algorithm || '-'} (${cert.public_key_size_bits || '?'} bits)`, "Information about the public key, including its algorithm (e.g., RSA, ECC) and size in bits.")}</tr>
        <tr><th>Signature Algo</th>${tdWithTooltip(cert.signature_algorithm || '-', "The algorithm used by the Certificate Authority (CA) to sign the certificate.")}</tr>
        <tr><th>SHA256 FP</th>${tdWithTooltip(`<span class="fingerprint">${cert.sha256_fingerprint || '-'}</span>`, "The SHA-256 fingerprint (hash) of the certificate, used to verify its integrity.")}</tr>
        <tr><th>Profile</th>${tdWithTooltip(cert.profile || '-', "Indicates the certificate profile or type, e.g., DV (Domain Validated), OV (Organization Validated), EV (Extended Validation).")}</tr>
        <tr><th>Is CA</th>${tdWithTooltip(cert.is_ca ? 'Yes' : 'No', "Indicates if this certificate is a Certificate Authority (CA) certificate, meaning it can sign other certificates.")}</tr>
        <tr><th>SANs</th>${tdWithTooltip((cert.san || []).join(', ') || '-', "Subject Alternative Names (SANs) are additional hostnames covered by this SSL certificate.")}</tr>
      </table>
      `}
    `).join('');
  }

  // Handle form submit
  form.addEventListener('submit', function(event) {
    event.preventDefault();
    loadingSpinner.style.display = 'block';

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
      if (!response.ok) {
        return response.text().then(text => { throw new Error(`Server error: ${response.status} ${text || response.statusText}`) });
      }
      return response.json();
    })
    .then(results => {
      loadingSpinner.style.display = 'none';
      resultsDiv.innerHTML = '';
      // Render summary and results
      renderSummary(results);
      if (Array.isArray(results)) {
        results.forEach((result, i) => resultsDiv.appendChild(renderResult(result, i)));
      } else {
        resultsDiv.appendChild(renderResult(results, 0));
      }
      // Initialize all tooltips on the page
// OCSP section
      // Use the first result if 'results' is an array, or 'results' itself if it's a single object.
      const displayableResultForOcsp = Array.isArray(results) ? (results.length > 0 ? results[0] : null) : results;

      if (displayableResultForOcsp) {
        const ocsp = displayableResultForOcsp.ocsp_check || {};
        const ocspStatusEl = document.getElementById('ocsp-status');
        const ocspUrlEl    = document.getElementById('ocsp-url');
        const ocspDetailEl = document.getElementById('ocsp-detail');

        if (ocspStatusEl && ocspUrlEl && ocspDetailEl) { // Check if elements exist
          if (!ocsp.checked) {
            ocspStatusEl.textContent = 'Skipped';
            ocspStatusEl.className   = 'text-warning';
            ocspUrlEl.textContent    = '';
            ocspDetailEl.textContent = '';
          } else {
            let statusText = '';
            switch (ocsp.status) {
              case 'good':
                statusText = '✔️ Good';
                ocspStatusEl.className = 'text-success';
                break;
              case 'revoked':
                statusText = '❌ Revoked';
                ocspStatusEl.className = 'text-danger';
                break;
              case 'unknown':
                statusText = '❓ Unknown';
                ocspStatusEl.className = 'text-secondary';
                break;
              default:
                statusText = '❌ Error';
                ocspStatusEl.className = 'text-danger';
            }
            ocspStatusEl.textContent = statusText;
            ocspUrlEl.textContent    = (ocsp.details && ocsp.details.checked_url) || '';
            ocspDetailEl.textContent = (ocsp.details && (ocsp.details.revocation_reason || ocsp.details.error)) || '';
          }
        }
      } else {
        // Clear OCSP fields if no result or elements exist but no data
        const ocspStatusEl = document.getElementById('ocsp-status');
        const ocspUrlEl    = document.getElementById('ocsp-url');
        const ocspDetailEl = document.getElementById('ocsp-detail');
        if (ocspStatusEl) {
          ocspStatusEl.textContent = 'N/A';
          ocspStatusEl.className = 'text-secondary';
        }
        if (ocspUrlEl) ocspUrlEl.textContent = '';
        if (ocspDetailEl) ocspDetailEl.textContent = '';
      }
      const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
      tooltipTriggerList.map(function (tooltipTriggerEl) {
        // Ensure tooltips are not re-initialized if they already exist
        if (!bootstrap.Tooltip.getInstance(tooltipTriggerEl)) {
          return new bootstrap.Tooltip(tooltipTriggerEl);
        }
        return null; // or bootstrap.Tooltip.getInstance(tooltipTriggerEl) if you need to return the instance
      });
    })
    .catch(error => {
      loadingSpinner.style.display = 'none';
      summaryTableWrapper.style.display = 'none';
      resultsDiv.innerHTML = `<div class="alert alert-danger"><strong>Error:</strong> ${error.message || error}</div>`;
    });
  });
});
