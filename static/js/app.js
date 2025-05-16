document.addEventListener('DOMContentLoaded', function() {
    const form = document.querySelector('form');
    const progressBar = document.getElementById('progress-bar');
    const resultsDiv = document.getElementById('results');

    form.addEventListener('submit', function(event) {
        event.preventDefault();

        progressBar.style.display = 'block';
        progressBar.querySelector('.progress-bar').style.width = '20%'; // Initial progress

        const formData = new FormData(form);

        // Extract and process domains
        const domainsString = formData.get('domains') || '';
        // Replace commas with spaces, then split by one or more spaces,
        // then filter out empty strings that might result from multiple spaces.
        const domainsArray = domainsString
            .replace(/,/g, ' ')
            .split(/\s+/)
            .filter(domain => domain.trim() !== '');

        // Extract other form values and ensure correct types
        const connectPort = parseInt(formData.get('connect_port'), 10) || 443;
        const insecure = formData.get('insecure') === 'true'; // Checkbox value is 'true' when checked
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
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        })
        .then(response => {
            progressBar.querySelector('.progress-bar').style.width = '70%'; // Almost complete
            return response.json();
        })
        .then(results => {
            progressBar.style.display = 'none';
            progressBar.querySelector('.progress-bar').style.width = '0%'; // Reset

            resultsDiv.innerHTML = ''; // Clear previous results
            results.forEach(result => {
                const resultCard = renderResult(result);
                resultsDiv.appendChild(resultCard);
            });
        })
        .catch(error => {
            progressBar.style.display = 'none';
            progressBar.querySelector('.progress-bar').style.width = '0%'; // Reset
            resultsDiv.innerHTML = `<div class="alert alert-danger">Error: ${error}</div>`;
        });
    });

    // Helper function to create a Bootstrap tooltip span (simplified)
    function get_tooltip_span(text) {
        const span = document.createElement('span');
        span.setAttribute('data-bs-toggle', 'tooltip');
        span.setAttribute('data-bs-placement', 'top');
        span.title = text;
        span.innerHTML = ' 🛈'; // Add a space before the icon
        return span;
    }

    // Helper function to create a section title
    function createSectionTitle(title, tooltipText) {
        const h5 = document.createElement('h5');
        h5.className = 'section-title';
        h5.textContent = title;
        if (tooltipText) {
            h5.appendChild(get_tooltip_span(tooltipText));
        }
        return h5;
    }
    
    // Helper function to format date strings
    function formatDate(dateString) {
        if (!dateString) return 'N/A';
        return dateString.replace("T", " ").replace("Z", "").replace("+00:00", "").substring(0, 19);
    }

    function renderResult(result) {
        const card = document.createElement('div');
        card.className = 'card mb-4 shadow-sm';

        const cardHeader = document.createElement('div');
        cardHeader.className = 'card-header';
        cardHeader.innerHTML = `<strong>${result.domain || 'N/A'}</strong>`;

        const status = result.status || 'failed';
        let statusBadgeHtml = '';
        if (status === 'completed') {
            statusBadgeHtml = '<span class="badge bg-success ms-2">COMPLETED</span>';
        } else if (status === 'completed_with_errors') {
            statusBadgeHtml = '<span class="badge bg-warning ms-2">COMPLETED WITH ERRORS</span>';
        } else {
            statusBadgeHtml = '<span class="badge bg-danger ms-2">FAILED</span>';
        }
        cardHeader.innerHTML += statusBadgeHtml;
        
        const cardBody = document.createElement('div');
        cardBody.className = 'card-body';

        if (result.error_message) {
            cardBody.innerHTML += `<div class="alert alert-danger"><strong>Overall Status:</strong> ${result.error_message}</div>`;
        }
        cardBody.innerHTML += `<p class="text-muted"><small>Analysis Time: ${result.analysis_timestamp || 'N/A'}</small></p>`;

        // Validation Section
        const valSection = document.createElement('div');
        valSection.appendChild(createSectionTitle('Validation', 'Whether the certificate is trusted by the system trust store.'));
        const val = result.validation || {};
        const val_status = val.system_trust_store;
        let valHtml = '';
        if (val_status === true) valHtml = "<span class='badge bg-success'>✔️ Valid (System Trust)</span>";
        else if (val_status === false) valHtml = `<span class='badge bg-danger'>❌ Invalid (System Trust)</span> ${val.error ? `<small class='text-muted ps-2'>(${val.error})</small>` : ''}`;
        else if (val.error) valHtml = `<span class='badge bg-danger'>❌ Error</span> <small class='text-muted ps-2'>(${val.error})</small>`;
        else valHtml = "<span class='badge bg-secondary'>N/A / Pending</span>";
        valSection.innerHTML += valHtml;
        cardBody.appendChild(valSection);

        const certs_list = result.certificates || [];
        const leaf_cert = certs_list.find(c => c.chain_index === 0 && !c.error);

        // Leaf Certificate Summary
        if (leaf_cert) {
            const leafSection = document.createElement('div');
            leafSection.appendChild(createSectionTitle('Leaf Certificate Summary', 'Summary of the leaf (end-entity) certificate.'));
            const table = document.createElement('table');
            table.className = 'table table-sm table-bordered';
            let tableHtml = `
                <tr><th>Common Name</th><td>${leaf_cert.common_name || 'N/A'}</td></tr>
                <tr><th>Expires</th><td>
                    ${formatDate(leaf_cert.not_after)}
                    ${leaf_cert.days_remaining !== undefined ? `<span class='${leaf_cert.days_remaining < 30 ? 'text-danger' : leaf_cert.days_remaining < 90 ? 'text-warning' : 'text-success'} fw-bold'> (${leaf_cert.days_remaining} days)</span>` : "<span class='text-secondary'>(Expiry N/A)</span>"}
                </td></tr>
                <tr><th>SANs</th><td>${(leaf_cert.san || []).join(", ") || 'None'}</td></tr>
                <tr><th>Issuer</th><td>${leaf_cert.issuer || 'N/A'}</td></tr>
            `;
            table.innerHTML = tableHtml;
            leafSection.appendChild(table);
            cardBody.appendChild(leafSection);
        }

        // Connection Health
        const connSection = document.createElement('div');
        connSection.appendChild(createSectionTitle('Connection Health', 'TLS version, cipher, and protocol health of the connection.'));
        const conn = result.connection_health || {};
        if (!conn.checked) {
            connSection.innerHTML += `<span class='badge bg-warning'>Not Checked / Failed</span> ${conn.error ? `<small class='text-muted ps-2'>(${conn.error})</small>` : ''}`;
        } else {
            const table = document.createElement('table');
            table.className = 'table table-sm table-bordered';
            let tls13Text = '';
            if (conn.supports_tls13 === true) tls13Text = "<span class='text-success'>✔️ Yes</span>";
            else if (conn.supports_tls13 === false) tls13Text = "<span class='text-danger'>❌ No</span>";
            else tls13Text = "<span class='text-secondary'>N/A</span>";
            table.innerHTML = `
                <tr><th>TLS Version</th><td>${conn.tls_version || 'N/A'}</td></tr>
                <tr><th>TLS 1.3 Support</th><td>${tls13Text}</td></tr>
                <tr><th>Cipher Suite</th><td>${conn.cipher_suite || 'N/A'}</td></tr>
            `;
            connSection.appendChild(table);
            if (conn.error) connSection.innerHTML += `<div class='alert alert-danger mt-2'><small>Connection Error: ${conn.error}</small></div>`;
        }
        cardBody.appendChild(connSection);

        // CRL Check
        const crlSection = document.createElement('div');
        crlSection.appendChild(createSectionTitle('CRL Check (Leaf Certificate)', 'Checks if the certificate is revoked using CRL.'));
        const crl_check_data = result.crl_check || {};
        if (!crl_check_data.checked) {
            crlSection.innerHTML += "<span class='badge bg-secondary'>Skipped</span>";
        } else {
            const crl_status = crl_check_data.leaf_status || 'error';
            const crl_details = crl_check_data.details || {};
            const crl_reason = typeof crl_details === 'object' && crl_details !== null && crl_details.reason ? crl_details.reason : 'No details';
            const crl_uri = typeof crl_details === 'object' && crl_details !== null && crl_details.checked_uri ? crl_details.checked_uri : null;
            
            let crlStatusHtml = '';
            if (crl_status === "good") crlStatusHtml = "<span class='badge bg-success'>✔️ Good</span>";
            else if (crl_status === "revoked") crlStatusHtml = "<span class='badge bg-danger'>❌ REVOKED</span>";
            else if (crl_status === "crl_expired") crlStatusHtml = "<span class='badge bg-warning'>⚠️ CRL Expired</span>";
            else if (crl_status === "unreachable") crlStatusHtml = "<span class='badge bg-warning'>⚠️ Unreachable</span>";
            else if (crl_status === "parse_error") crlStatusHtml = "<span class='badge bg-danger'>❌ Parse Error</span>";
            else if (crl_status === "no_cdp") crlStatusHtml = "<span class='badge bg-info'>ℹ️ No CDP</span>";
            else if (crl_status === "no_http_cdp") crlStatusHtml = "<span class='badge bg-info'>ℹ️ No HTTP CDP</span>";
            else if (crl_status === "error") crlStatusHtml = "<span class='badge bg-danger'>❌ Error</span>";
            else crlStatusHtml = "<span class='badge bg-secondary'>❓ Unknown</span>";
            
            crlSection.innerHTML += crlStatusHtml;
            crlSection.innerHTML += `<p class='text-muted mt-1'><small>${crl_reason}${crl_uri ? `<br>Checked URI: ${crl_uri}` : ''}</small></p>`;
        }
        cardBody.appendChild(crlSection);

        // Certificate Chain Details
        const chainSection = document.createElement('div');
        chainSection.appendChild(createSectionTitle('Certificate Chain Details', 'Details of each certificate in the chain.'));
        if (!certs_list.length && result.status !== 'failed') {
            chainSection.innerHTML += "<div class='alert alert-warning'>No certificates were processed successfully.</div>";
        } else if (!certs_list.length && result.status === 'failed') {
            chainSection.innerHTML += "<div class='alert alert-danger'>Certificate fetching or analysis failed.</div>";
        }
        certs_list.forEach((cert, index) => {
            const certDiv = document.createElement('div');
            let titleHtml = `<h6 class="mt-3">Certificate #${index + 1}`;
            if (cert.error) titleHtml += " <span class='text-danger'>(Error Analyzing)</span>";
            else if (cert.chain_index === 0) titleHtml += " (Leaf)";
            else if (cert.is_ca) titleHtml += " (CA/Intermediate)";
            else titleHtml += " (Intermediate)";
            titleHtml += "</h6>";
            certDiv.innerHTML = titleHtml;

            if (cert.error) {
                certDiv.innerHTML += `<div class='cert-error'><strong>Error:</strong> ${cert.error}</div>`;
            } else {
                const table = document.createElement('table');
                table.className = 'table table-sm table-bordered mb-3';
                let days_remaining_html = '';
                if (cert.days_remaining !== undefined) {
                    const days_class = cert.days_remaining < 30 ? 'text-danger' : cert.days_remaining < 90 ? 'text-warning' : 'text-success';
                    days_remaining_html = `<span class='${days_class} fw-bold'> (${cert.days_remaining} days remaining)</span>`;
                } else {
                    days_remaining_html = "<span class='text-secondary'>(Expiry N/A)</span>";
                }

                let key_html = `${cert.public_key_algorithm || 'N/A'}`;
                if (cert.public_key_size_bits) {
                    const k_algo = cert.public_key_algorithm || '';
                    const k_size = cert.public_key_size_bits;
                    const weak_key = (k_algo === 'RSA' && k_size < 2048) || (k_algo.includes('ECDSA') && k_size < 256) || (k_algo === 'DSA' && k_size < 2048);
                    key_html += ` (<span class='${weak_key ? 'weak-crypto' : ''}'>${k_size} bits</span>)${weak_key ? "<span class='weak-crypto ps-1'>(Weak)</span>" : ""}`;
                }
                
                let sig_algo_html = `${cert.signature_algorithm || 'N/A'}`;
                const weak_hash = cert.signature_algorithm && (cert.signature_algorithm.toLowerCase().includes("sha1") || cert.signature_algorithm.toLowerCase().includes("md5"));
                if (weak_hash) {
                    sig_algo_html = `<span class='weak-crypto'>${sig_algo_html}</span><span class='weak-crypto ps-1'>(Weak)</span>`;
                }

                let is_ca_html = 'N/A';
                if (cert.is_ca === true) is_ca_html = `Yes (PathLen: ${cert.path_length_constraint !== undefined ? cert.path_length_constraint : 'None'})`;
                else if (cert.is_ca === false) is_ca_html = 'No';
                
                let sct_html = "<span class='text-secondary'>N/A</span>";
                if (cert.has_scts === true) sct_html = "<span class='text-success'>✔️ Yes</span>";
                else if (cert.has_scts === false) sct_html = "<span class='text-warning'>❌ No</span>";


                table.innerHTML = `
                    <tr><th>Subject</th><td>${cert.subject || 'N/A'}</td></tr>
                    <tr><th>Issuer</th><td>${cert.issuer || 'N/A'}</td></tr>
                    <tr><th>Common Name</th><td>${cert.common_name || 'N/A'}</td></tr>
                    <tr><th>Serial</th><td>${cert.serial_number || 'N/A'}</td></tr>
                    <tr><th>Version</th><td>${cert.version || 'N/A'}</td></tr>
                    <tr><th>Validity</th><td>
                        ${formatDate(cert.not_before)} → ${formatDate(cert.not_after)} <br>
                        ${days_remaining_html}
                    </td></tr>
                    <tr><th>Key</th><td>${key_html}</td></tr>
                    <tr><th>Signature Algo</th><td>${sig_algo_html}</td></tr>
                    <tr><th>SHA256 FP</th><td class='fingerprint'>${cert.sha256_fingerprint || 'N/A'}</td></tr>
                    <tr><th>Profile</th><td>${cert.profile || 'N/A'}</td></tr>
                    <tr><th>Is CA</th><td>${is_ca_html}</td></tr>
                    <tr><th>Embedded SCTs</th><td>${sct_html}</td></tr>
                `;
                certDiv.appendChild(table);
            }
            chainSection.appendChild(certDiv);
        });
        cardBody.appendChild(chainSection);

        // Certificate Transparency
        const transSection = document.createElement('div');
        transSection.appendChild(createSectionTitle('Certificate Transparency (crt.sh)', 'Checks for issued certificates in public CT logs.'));
        const trans = result.transparency || {};
        if (!trans.checked) {
            transSection.innerHTML += "<span class='badge bg-secondary'>Skipped</span>";
        } else if (trans.errors && Object.keys(trans.errors).length > 0) {
            transSection.innerHTML += "<span class='badge bg-danger'>Error</span>";
            const ul = document.createElement('ul');
            for (const d in trans.errors) {
                const li = document.createElement('li');
                li.innerHTML = `<strong>${d}</strong>: ${trans.errors[d]}`;
                if (trans.crtsh_report_links && trans.crtsh_report_links[d]) {
                    li.innerHTML += ` <a href="${trans.crtsh_report_links[d]}" target="_blank" rel="noopener" class="ms-2">[View on crt.sh]</a>`;
                }
                ul.appendChild(li);
            }
            transSection.appendChild(ul);
        } else if (trans.details && Object.keys(trans.details).length > 0) {
            const ul = document.createElement('ul');
            for (const d in trans.details) {
                const li = document.createElement('li');
                const records = trans.details[d];
                li.innerHTML = `<strong>${d}</strong>: `;
                if (records === null || records === undefined) { // Check for null or undefined explicitly
                    li.innerHTML += "<span class='badge bg-danger'>Error fetching records</span>";
                } else {
                     li.innerHTML += `<span class='badge bg-info'>${records.length} record(s)</span>`;
                }
                if (trans.crtsh_report_links && trans.crtsh_report_links[d]) {
                    li.innerHTML += ` <a href="${trans.crtsh_report_links[d]}" target="_blank" rel="noopener" class="ms-2">[View on crt.sh]</a>`;
                }
                ul.appendChild(li);
            }
            transSection.appendChild(ul);
            transSection.innerHTML += `<span class='ps-2'>Total records found:</span> <span class='badge bg-info'>${trans.crtsh_records_found || 0}</span>`;
        } else {
             transSection.innerHTML += "<span class='badge bg-info'>No records found or not applicable.</span>";
        }
        cardBody.appendChild(transSection);


        card.appendChild(cardHeader);
        card.appendChild(cardBody);
        return card;
    }
});
