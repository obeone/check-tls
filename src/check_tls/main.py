# CLI entry point and argument parsing
import argparse
import logging
from urllib.parse import urlparse # Added for URL parsing
from check_tls.tls_checker import run_analysis, analyze_certificates, get_log_level
from check_tls.web_server import run_server


def print_human_summary(results):
    """
    Print a well-formatted, colorized summary of TLS analysis results for each domain.

    Parameters:
        results (list): List of dictionaries containing TLS analysis results per domain.

    Returns:
        None

    The output is designed for maximum readability in a standard terminal.
    """
    separator = "\n" + "=" * 70 + "\n"
    for result in results:
        domain = result.get('domain', 'N/A')
        status = result.get('status', 'N/A')

        # Print header separator and domain status
        print(separator)
        print(f"\033[1mTLS Analysis for domain: {domain}\033[0m")
        print(f"Status: \033[1m{status}\033[0m")

        # Print error message if present
        if result.get('error_message'):
            print(f"Error: \033[91m{result['error_message']}\033[0m")

        # Connection Health Section
        conn = result.get('connection_health', {})
        print("\n\033[1mConnection Health:\033[0m")
        if not conn.get('checked'):
            print("  TLS Version : \033[93mNot Checked / Failed\033[0m")
        else:
            print(f"  TLS Version : {conn.get('tls_version', 'N/A')}")
            tls13_support = conn.get('supports_tls13')
            tls13_text = (
                '\033[92mYes\033[0m' if tls13_support is True else
                ('\033[91mNo\033[0m' if tls13_support is False else '\033[93mN/A\033[0m')
            )
            print(f"  TLS 1.3     : {tls13_text}")
            print(f"  Cipher Suite: {conn.get('cipher_suite', 'N/A')}")
            if conn.get('error'):
                print(f"  Error       : \033[91m{conn['error']}\033[0m")

        # Certificate Validation Section
        val = result.get('validation', {})
        sys_val = val.get('system_trust_store')
        val_status = sys_val
        print("\n\033[1mCertificate Validation:\033[0m")
        if val_status is True:
            val_text = '\033[92m✔️ Valid (System Trust)\033[0m'
        elif val_status is False:
            val_text = '\033[91m❌ Invalid (System Trust)'
            if val.get('error'):
                val_text += f" ({val['error']})"
            val_text += '\033[0m'
        elif val.get('error'):
            val_text = f"\033[91m❌ Error ({val['error']})\033[0m"
        else:
            val_text = "\033[93m❓ Unknown/Skipped\033[0m"
        print(f"  {val_text}")

        # Leaf Certificate Summary
        certs_list = result.get('certificates', [])
        leaf_cert_data = certs_list[0] if certs_list and 'error' not in certs_list[0] else None
        if leaf_cert_data:
            print("\n\033[1mLeaf Certificate Summary:\033[0m")
            print(
                f"  Common Name: \033[96m{leaf_cert_data.get('common_name', 'N/A')}\033[0m")
            days_left_leaf = leaf_cert_data.get('days_remaining', None)
            expiry_text_leaf = leaf_cert_data.get('not_after', 'N/A')
            if days_left_leaf is not None:
                expiry_color_leaf = (
                    '\033[91m' if days_left_leaf < 30 else
                    ('\033[93m' if days_left_leaf < 90 else '\033[92m')
                )
                expiry_text_leaf += f" ({expiry_color_leaf}{days_left_leaf} days remaining\033[0m)"
            else:
                expiry_text_leaf += " (\033[93mExpiry N/A\033[0m)"
            print(f"  Expires    : {expiry_text_leaf}")
            sans_leaf = leaf_cert_data.get('san', [])
            max_sans_display = 5
            sans_display = ', '.join(sans_leaf[:max_sans_display])
            if len(sans_leaf) > max_sans_display:
                sans_display += f", ... ({len(sans_leaf) - max_sans_display} more)"
            print(
                f"  SANs       : {sans_display if sans_leaf else 'None'}")
            print(f"  Issuer     : {leaf_cert_data.get('issuer', 'N/A')}")

        # CRL Check Section
        print("\n\033[1mCRL Check (Leaf):\033[0m")
        crl_check_data = result.get('crl_check', {})
        if not crl_check_data.get('checked'):
            print("  Status      : \033[93mSkipped\033[0m")
        else:
            crl_status = crl_check_data.get('leaf_status', 'error')
            crl_details = crl_check_data.get('details', {})
            crl_reason = (
                crl_details.get('reason', 'No details available.')
                if isinstance(crl_details, dict) else 'Invalid details format.'
            )
            crl_uri = crl_details.get('checked_uri') if isinstance(
                crl_details, dict) else None
            status_map = {
                "good": "\033[92m✔️ Good\033[0m",
                "revoked": "\033[91m❌ REVOKED\033[0m",
                "crl_expired": "\033[93m⚠️ CRL Expired\033[0m",
                "unreachable": "\033[93m⚠️ Unreachable\033[0m",
                "parse_error": "\033[91m❌ Parse Error\033[0m",
                "no_cdp": "\033[94mℹ️ No CDP\033[0m",
                "no_http_cdp": "\033[94mℹ️ No HTTP CDP\033[0m",
                "error": "\033[91m❌ Error\033[0m"
            }
            status_text = status_map.get(
                crl_status, "\033[93m❓ Unknown\033[0m")
            print(f"  Status      : {status_text}")
            print(f"  Detail      : {crl_reason}")
            if crl_uri:
                print(f"  Checked URI : {crl_uri}")

        # Certificate Chain Details
        # This section prints each certificate in the chain with improved color, formatting, and readability.
        cert_count_color = '\033[92m' if certs_list else '\033[91m'
        print(
            f"\n\033[1mCertificate Chain Details:\033[0m ({cert_count_color}{len(certs_list)} found\033[0m)")
        if not certs_list and result.get('status') != 'failed':
            print(
                "  \033[93m⚠️ No certificates were processed successfully.\033[0m")
        for cert in certs_list:
            chain_index = cert.get('chain_index', '?')

            # Determine emoji based on certificate position in chain
            if chain_index == 0:
                chain_emoji = "🔒"  # Leaf certificate
            elif isinstance(chain_index, int) and chain_index == len(certs_list) - 1:
                chain_emoji = "🏁"  # Root certificate
            else:
                chain_emoji = "🔗"  # Intermediate certificate

            # Print error if present in certificate
            if 'error' in cert:
                print(
                    f"  [{chain_emoji} Chain Index {chain_index}] \033[91m\033[1m❌ Error: {cert['error']}\033[0m")
                continue

            # Print certificate details
            print(
                f"  [{chain_emoji} Chain Index {chain_index}] \033[1mSubject:\033[0m \033[96m{cert.get('subject', 'N/A')}\033[0m")
            print(
                f"      \033[1mIssuer:\033[0m \033[94m{cert.get('issuer', 'N/A')}\033[0m")
            print(
                f"      \033[1mSerial:\033[0m {cert.get('serial_number', 'N/A')} | \033[1mProfile:\033[0m {cert.get('profile', 'N/A')}")

            # Format and print validity period with color and emoji
            days_left = cert.get('days_remaining', None)
            not_before = cert.get('not_before', 'N/A')
            not_after = cert.get('not_after', 'N/A')
            if days_left is not None and isinstance(days_left, int):
                if days_left < 0:
                    expiry_color = '\033[91m'
                    expiry_emoji = '❌'
                elif days_left < 30:
                    expiry_color = '\033[91m'
                    expiry_emoji = '⚠️'
                elif days_left < 90:
                    expiry_color = '\033[93m'
                    expiry_emoji = '⏳'
                else:
                    expiry_color = '\033[92m'
                    expiry_emoji = '✅'
                expiry_str = f"{not_before} -> {not_after} | {expiry_color}{days_left} days left {expiry_emoji}\033[0m"
            else:
                expiry_str = f"{not_before} -> {not_after} | \033[93mN/A days left\033[0m"
            print(f"      \033[1mValid:\033[0m {expiry_str}")

            # Print public key algorithm and size
            print(
                f"      \033[1mPublic Key:\033[0m {cert.get('public_key_algorithm', 'N/A')} (\033[1m{cert.get('public_key_size_bits', 'N/A')} bits\033[0m)")

            # Print signature algorithm
            print(
                f"      \033[1mSignature:\033[0m {cert.get('signature_algorithm', 'N/A')}")

            # Print SHA256 fingerprint
            print(
                f"      \033[1mSHA256 Fingerprint:\033[0m {cert.get('sha256_fingerprint', 'N/A')}")

            # Print Subject Alternative Names (SANs)
            sans = cert.get('san', [])
            if sans:
                max_sans_display = 5
                sans_display = ', '.join(sans[:max_sans_display])
                if len(sans) > max_sans_display:
                    sans_display += f", ... (\033[90m{len(sans) - max_sans_display} more\033[0m)"
                print(f"      \033[1mSANs:\033[0m {sans_display}")
            else:
                print(f"      \033[1mSANs:\033[0m None")

            # Extra newline for readability
            print("")

        # Certificate Transparency Section
        trans = result.get('transparency', {})
        print("\n\033[1mCertificate Transparency:\033[0m")
        if not trans.get('checked'):
            print("  Status: \033[93m⚠️ Skipped\033[0m")
        else:
            details = trans.get('details', {})
            links = trans.get('crtsh_report_links', {})
            total = trans.get('crtsh_records_found', 0)
            if trans.get('errors'):
                print("  \033[91mErrors found in transparency logs:\033[0m")
                for d, err in trans['errors'].items():
                    link = links.get(d)
                    print(f"    ❌ {d}: Error: {err}" +
                          (f" [crt.sh]({link})" if link else ""))
            else:
                print("  \033[92mTransparency log records:\033[0m")
                for d, records in details.items():
                    link = links.get(d)
                    count = len(
                        records) if records is not None else 'Error'
                    print(f"    ✅ {d}: {count} record(s)" +
                          (f" [crt.sh]({link})" if link else ""))
            print(f"\n  \033[1mTotal records found:\033[0m {total}")

    # Print footer separator and end message
    print(separator)
    print("\033[90m--- End of analysis ---\033[0m\n")


def main():
    """
    Main function to parse command-line arguments and execute TLS analysis or run the web server.

    Parameters:
        None

    Returns:
        None

    This function handles the following:
    - Parsing command-line arguments for domains to analyze, output formats, log level, and other options.
    - Setting up logging based on the provided log level.
    - Running the web server if the `--server` flag is set.
    - Performing TLS analysis for specified domains and outputting results in the requested format.
    """
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Analyze TLS certificates for one or more domains.")
    parser.add_argument('domains', nargs='*', help='Domains to analyze (e.g., google.com or google.com:443)')
    parser.add_argument('-P', '--connect-port', type=int, default=443,
                        help='Port to connect to for TLS analysis (default: 443). This is overridden if port is specified in domain string e.g. example.com:1234')
    parser.add_argument('-j', '--json', type=str,
                        help='Output JSON report to FILE (use "-" for stdout)', default=None)
    parser.add_argument('-c', '--csv', type=str,
                        help='Output CSV report to FILE (use "-" for stdout)', default=None)
    parser.add_argument('-m', '--mode', type=str, choices=[
                        'simple', 'full'], default='full', help="Choose mode: 'simple' or 'full' (default: full)")
    parser.add_argument('-l', '--loglevel', type=str,
                        default='WARNING', help='Set log level (default: WARN)')
    parser.add_argument('-k', '--insecure', action='store_true',
                        help='Allow fetching certificates without validation (self-signed)')
    parser.add_argument('-s', '--server', action='store_true',
                        help='Run as HTTP server with web interface')
    parser.add_argument('-p', '--port', type=int, default=8000,
                        help='Specify server port (default: 8000)')
    parser.add_argument('--no-transparency', action='store_true',
                        help='Skip crt.sh certificate transparency check')
    parser.add_argument('--no-crl-check', action='store_true',
                        help='Disable CRL check for the leaf certificate (experimental)')
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(level=get_log_level(args.loglevel))

    # Check if no domains or server mode is specified
    if not args.domains and not args.server:
        parser.print_help()
        return

    # Run the web server if the --server flag is set
    if args.server:
        run_server(args)
    else:
        # Perform TLS analysis for specified domains
        if args.domains:
            # Process domains to extract host and port, using --connect-port as default if not specified in domain string
            parsed_domains_for_analysis = []
            for domain_entry in args.domains:
                # Ensure a scheme is present for urlparse to work correctly, default to https if missing
                # This helps parse "example.com:443" as well as "https://example.com:443"
                # However, urlparse might misinterpret "example.com:443" if no scheme is forced.
                # A simple check: if "://" is not in the entry, prepend "https://"
                # This is a basic heuristic. More robust parsing might be needed for all edge cases.
                
                processed_entry = domain_entry
                if "://" not in processed_entry:
                    # If it looks like "host:port" or just "host", prepend scheme
                    # This handles cases like "google.com" or "google.com:443"
                    # For "google.com:notaport", urlparse might still struggle.
                    # We assume if a colon is present and it's not part of a scheme, it's for a port.
                    # A more direct approach for host:port without scheme:
                    parts_check = processed_entry.split(':', 1)
                    if len(parts_check) > 1 and parts_check[1].isdigit():
                         # Likely "host:port" format, urlparse might treat "host" as scheme
                         # Prepending https:// ensures hostname and port are correctly parsed.
                         processed_entry = f"https://{processed_entry}"
                    elif ':' not in processed_entry: # Just a domain name
                        processed_entry = f"https://{processed_entry}"
                    # If it's like "some-scheme:actualdata" and not http/https, urlparse will handle it.

                parsed_url = urlparse(processed_entry)
                
                host = parsed_url.hostname
                port = parsed_url.port

                if not host: # Handle cases where parsing might fail to extract a hostname
                    logging.warning(f"Could not extract hostname from '{domain_entry}'. Using the entry as is for host and default port.")
                    # Fallback to old behavior or a modified version if urlparse fails badly
                    parts = domain_entry.split(':', 1)
                    host = parts[0] # This might be the scheme if urlparse failed, e.g. "mailto:test"
                    port = args.connect_port # Default port
                    if len(parts) > 1:
                        try:
                            port_val = int(parts[1])
                            if 1 <= port_val <= 65535:
                                port = port_val
                        except ValueError:
                            # Port part was not a valid number, stick to default
                            pass # port remains args.connect_port
                
                if port is None: # If port was not in the URL
                    port = args.connect_port # Use default CLI port

                # Final validation for port, even if extracted by urlparse or set by default
                if not (1 <= port <= 65535):
                    logging.warning(f"Port {port} for host {host} (from '{domain_entry}') is invalid. Using default/CLI port {args.connect_port}.")
                    port = args.connect_port
                    
                parsed_domains_for_analysis.append({'host': host, 'port': port, 'original_entry': domain_entry})

            results = []
            for item in parsed_domains_for_analysis:
                results.append(
                    analyze_certificates(
                        domain=item['host'],
                        port=item['port'],
                        mode=args.mode,
                        insecure=args.insecure,
                        skip_transparency=args.no_transparency,
                        perform_crl_check=not args.no_crl_check
                    )
                )

            # Output results in the requested format
            # run_analysis now expects a list of "domain:port" strings or just "domain" strings
            # It will use its own default port (443) if not specified in the string.
            # We pass the original args.domains list which contains the user's input strings.
            if args.json or args.csv:
                run_analysis(
                    domains_input=args.domains, # Pass the original list of domain strings
                    output_json=args.json,
                    output_csv=args.csv,
                    mode=args.mode,
                    insecure=args.insecure,
                    skip_transparency=args.no_transparency,
                    perform_crl_check=not args.no_crl_check
                    # The run_analysis function will handle parsing port from domain strings
                    # or use its default of 443 if not present.
                    # The --connect-port arg is primarily for the direct analyze_certificates call above
                    # for the human_summary, or if run_analysis was to be refactored to take a default port.
                )
            else:
                print_human_summary(results)
        else:
            parser.print_help()


if __name__ == "__main__":
    main()
