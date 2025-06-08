# src/check_tls/main.py

import argparse
import logging
import sys
import shtab  # Import shtab
from urllib.parse import urlparse
from check_tls import __version__
from check_tls.tls_checker import run_analysis, analyze_certificates, get_log_level
from check_tls.web_server import run_server, get_flask_app

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
        # Uses ANSI escape codes for bold text (\033[1m) and reset (\033[0m)
        print(separator)
        print(f"\033[1mTLS Analysis for domain: {domain}\033[0m")
        print(f"Status: \033[1m{status}\033[0m")

        # Print error message if present (uses red color \033[91m)
        if result.get('error_message'):
            print(f"Error: \033[91m{result['error_message']}\033[0m")

        # Connection Health Section
        # Displays TLS version, TLS 1.3 support, and cipher suite.
        conn = result.get('connection_health', {})
        print("\n\033[1mConnection Health:\033[0m")
        # Check if connection health was successfully checked
        if not conn.get('checked'):
            # Display warning if not checked (uses yellow color \033[93m)
            print("  TLS Version : \033[93mNot Checked / Failed\033[0m")
        else:
            print(f"  TLS Version : {conn.get('tls_version', 'N/A')}")
            tls13_support = conn.get('supports_tls13')
            # Determine TLS 1.3 support text and color based on boolean value
            tls13_text = (
                '\033[92mYes\033[0m' if tls13_support is True else # Green for Yes (\033[92m)
                ('\033[91mNo\033[0m' if tls13_support is False else '\033[93mN/A\033[0m') # Red for No (\033[91m), Yellow for N/A (\033[93m)
            )
            print(f"  TLS 1.3     : {tls13_text}")
            print(f"  Cipher Suite: {conn.get('cipher_suite', 'N/A')}")
            # Print connection error if present (uses red color \033[91m)
            if conn.get('error'):
                print(f"  Error       : \033[91m{conn['error']}\033[0m")

        # Certificate Validation Section
        # Displays the result of validation against the system trust store.
        val = result.get('validation', {})
        sys_val = val.get('system_trust_store')
        val_status = sys_val # Alias for clarity
        print("\n\033[1mCertificate Validation:\033[0m")
        # Determine validation status text and color
        if val_status is True:
            val_text = '\033[92m✔️ Valid (System Trust)\033[0m' # Green for Valid (\033[92m)
        elif val_status is False:
            val_text = '\033[91m❌ Invalid (System Trust)' # Red for Invalid (\033[91m)
            # Append error message if available
            if val.get('error'):
                val_text += f" ({val['error']})"
            val_text += '\033[0m'
        elif val.get('error'):
            val_text = f"\033[91m❌ Error ({val['error']})\033[0m" # Red for Error (\033[91m)
        else:
            val_text = "\033[93m❓ Unknown/Skipped\033[0m" # Yellow for Unknown/Skipped (\033[93m)
        print(f"  {val_text}")

        # Leaf Certificate Summary
        # Provides key details about the first certificate in the chain (the leaf certificate).
        certs_list = result.get('certificates', [])
        # Get the first certificate data if available and no error occurred during its processing
        leaf_cert_data = certs_list[0] if certs_list and 'error' not in certs_list[0] else None
        if leaf_cert_data:
            print("\n\033[1mLeaf Certificate Summary:\033[0m")
            # Common Name (uses cyan color \033[96m)
            print(
                f"  Common Name: \033[96m{leaf_cert_data.get('common_name', 'N/A')}\033[0m")
            days_left_leaf = leaf_cert_data.get('days_remaining', None)
            expiry_text_leaf = leaf_cert_data.get('not_after', 'N/A')
            # Format expiry date and add days remaining with color coding
            if days_left_leaf is not None:
                expiry_color_leaf = (
                    '\033[91m' if days_left_leaf < 30 else # Red for less than 30 days (\033[91m)
                    ('\033[93m' if days_left_leaf < 90 else '\033[92m') # Yellow for less than 90 days (\033[93m), Green otherwise (\033[92m)
                )
                expiry_text_leaf += f" ({expiry_color_leaf}{days_left_leaf} days remaining\033[0m)"
            else:
                expiry_text_leaf += " (\033[93mExpiry N/A\033[0m)" # Yellow for N/A (\033[93m)
            print(f"  Expires    : {expiry_text_leaf}")
            sans_leaf = leaf_cert_data.get('san', [])
            max_sans_display = 5
            # Display a limited number of SANs, indicating if there are more
            sans_display = ', '.join(sans_leaf[:max_sans_display])
            if len(sans_leaf) > max_sans_display:
                sans_display += f", ... ({len(sans_leaf) - max_sans_display} more)"
            print(
                f"  SANs       : {sans_display if sans_leaf else 'None'}")
            print(f"  Issuer     : {leaf_cert_data.get('issuer', 'N/A')}")

        # CRL Check Section
        # Displays the result of the Certificate Revocation List check for the leaf certificate.
        print("\n\033[1mCRL Check (Leaf):\033[0m")
        crl_check_data = result.get('crl_check', {})
        # Check if CRL check was performed
        if not crl_check_data.get('checked'):
            print("  Status      : \033[93mSkipped\033[0m") # Yellow for Skipped (\033[93m)
        else:
            crl_status = crl_check_data.get('leaf_status', 'error')
            crl_details = crl_check_data.get('details', {})
            # Extract CRL reason, handling potential format issues
            crl_reason = (
                crl_details.get('reason', 'No details available.')
                if isinstance(crl_details, dict) else 'Invalid details format.'
            )
            # Extract checked CRL URI
            crl_uri = crl_details.get('checked_uri') if isinstance(
                crl_details, dict) else None
            # Map CRL status strings to colorized text with emojis
            status_map = {
                "good": "\033[92m✔️ Good\033[0m", # Green (\033[92m)
                "revoked": "\033[91m❌ REVOKED\033[0m", # Red (\033[91m)
                "crl_expired": "\033[93m⚠️ CRL Expired\033[0m", # Yellow (\033[93m)
                "unreachable": "\033[93m⚠️ Unreachable\033[0m", # Yellow (\033[93m)
                "parse_error": "\033[91m❌ Parse Error\033[0m", # Red (\033[91m)
                "no_cdp": "\033[94mℹ️ No CDP\033[0m", # Blue (\033[94m)
                "no_http_cdp": "\033[94mℹ️ No HTTP CDP\033[0m", # Blue (\033[94m)
                "error": "\033[91m❌ Error\033[0m" # Red (\033[91m)
            }
            status_text = status_map.get(
                crl_status, "\033[93m❓ Unknown\033[0m") # Default to Yellow Unknown (\033[93m)
            print(f"  Status      : {status_text}")
            print(f"  Detail      : {crl_reason}")
            if crl_uri:
                print(f"  Checked URI : {crl_uri}")

        # OCSP section
        print("\n\033[1mOCSP Check (Leaf):\033[0m")
        ocsp_check = result.get("ocsp_check", {})
        if not ocsp_check.get("checked"):
            print("  Status      : \033[93mSkipped\033[0m")  # Yellow for Skipped
        else:
            status = ocsp_check.get("status", "error")
            details = ocsp_check.get("details", {}) # Ensure details is a dict
            checked_url = ocsp_check.get("checked_url", "N/A")

            # Map OCSP status to colorized text
            ocsp_status_map = {
                "good": "\033[92m✔️ Good\033[0m",  # Green
                "revoked": "\033[91m❌ REVOKED\033[0m",  # Red
                "unknown": "\033[93m❓ Unknown\033[0m",  # Yellow
                "error": "\033[91m❌ Error\033[0m"  # Red
            }
            status_text = ocsp_status_map.get(status, "\033[91m❌ Error\033[0m") # Default to Red Error

            print(f"  Status      : {status_text}")
            print(f"  Checked URL : {checked_url}")

            # Display revocation reason or error
            revocation_reason = details.get("revocation_reason")
            error_message = details.get("error")
            if revocation_reason:
                print(f"  Detail      : {revocation_reason}")
            elif error_message:
                print(f"  Detail      : \033[91m{error_message}\033[0m") # Red for error message
            else:
                print("  Detail      : No additional details.")

        # Certificate Chain Details
        # Lists details for each certificate in the chain, including intermediates and root.
        # Colorize the count based on whether certificates were found.
        cert_count_color = '\033[92m' if certs_list else '\033[91m' # Green if found, Red if not
        print(
            f"\n\033[1mCertificate Chain Details:\033[0m ({cert_count_color}{len(certs_list)} found\033[0m)")
        # Display a warning if no certificates were processed successfully, unless the overall status was 'failed'
        if not certs_list and result.get('status') != 'failed':
            print(
                "  \033[93m⚠️ No certificates were processed successfully.\033[0m") # Yellow warning (\033[93m)
        # Iterate through each certificate in the chain
        for cert in certs_list:
            chain_index = cert.get('chain_index', '?')

            # Determine emoji based on chain index (position in the chain)
            if chain_index == 0:
                chain_emoji = "🔒"  # Leaf certificate (first in chain)
            elif isinstance(chain_index, int) and chain_index == len(certs_list) - 1:
                chain_emoji = "🏁"  # Root certificate (assuming last is root)
            else:
                chain_emoji = "🔗"  # Intermediate certificate

            # Handle errors specific to processing a single certificate in the chain
            if 'error' in cert:
                print(
                    f"  [{chain_emoji} Chain Index {chain_index}] \033[91m\033[1m❌ Error: {cert['error']}\033[0m") # Red and bold for error (\033[91m\033[1m)
                continue # Skip to the next certificate if there's an error

            # Print certificate details with color coding
            print(
                f"  [{chain_emoji} Chain Index {chain_index}] \033[1mSubject:\033[0m \033[96m{cert.get('subject', 'N/A')}\033[0m") # Subject in cyan (\033[96m)
            print(
                f"      \033[1mIssuer:\033[0m \033[94m{cert.get('issuer', 'N/A')}\033[0m") # Issuer in blue (\033[94m)
            print(
                f"      \033[1mSerial:\033[0m {cert.get('serial_number', 'N/A')} | \033[1mProfile:\033[0m {cert.get('profile', 'N/A')}")

            days_left = cert.get('days_remaining', None)
            not_before = cert.get('not_before', 'N/A')
            not_after = cert.get('not_after', 'N/A')
            # Format validity period and add days remaining with color coding and emojis
            if days_left is not None and isinstance(days_left, int):
                if days_left < 0:
                    expiry_color = '\033[91m' # Red for expired (\033[91m)
                    expiry_emoji = '❌'
                elif days_left < 10:
                    expiry_color = '\033[91m' # Red for less than 30 days (\033[91m)
                    expiry_emoji = '⚠️'
                elif days_left < 30:
                    expiry_color = '\033[93m' # Yellow for less than 90 days (\033[93m)
                    expiry_emoji = '⏳'
                else:
                    expiry_color = '\033[92m' # Green otherwise (\033[92m)
                    expiry_emoji = '✅'
                expiry_str = f"{not_before} -> {not_after} | {expiry_color}{days_left} days left {expiry_emoji}\033[0m"
            else:
                expiry_str = f"{not_before} -> {not_after} | \033[93mN/A days left\033[0m" # Yellow for N/A (\033[93m)
            print(f"      \033[1mValid:\033[0m {expiry_str}")

            pub_key_algo = cert.get('public_key_algorithm', 'N/A')
            pub_key_size = cert.get('public_key_size_bits', 'N/A')
            print(
                f"      \033[1mPublic Key:\033[0m {pub_key_algo} (\033[1m{pub_key_size} bits\033[0m)")
            print(
                f"      \033[1mSignature:\033[0m {cert.get('signature_algorithm', 'N/A')}")
            print(
                f"      \033[1mSHA256 FP:\033[0m {cert.get('sha256_fingerprint', 'N/A')}")

            sans = cert.get('san', [])
            # Display a limited number of SANs for chain certificates, indicating if there are more
            if sans:
                max_sans_display = 5
                sans_display = ', '.join(sans[:max_sans_display])
                if len(sans) > max_sans_display:
                    sans_display += f", ... (\033[90m{len(sans) - max_sans_display} more\033[0m)" # Grey for 'more' count (\033[90m)
                print(f"      \033[1mSANs:\033[0m {sans_display}")
            else:
                print(f"      \033[1mSANs:\033[0m None")

            print("")  # Extra newline for readability between certs

        # Certificate Transparency Section
        # Displays information found on crt.sh for the certificates.
        trans = result.get('transparency', {})
        print("\n\033[1mCertificate Transparency:\033[0m")
        # Check if transparency check was performed
        if not trans.get('checked'):
            print("  Status: \033[93m⚠️ Skipped\033[0m") # Yellow for Skipped (\033[93m)
        else:
            details = trans.get('details', {})
            links = trans.get('crtsh_report_links', {})
            total = trans.get('crtsh_records_found', 0)
            # Display errors encountered during the crt.sh query
            if trans.get('errors'):
                print("  \033[91mErrors found during crt.sh query:\033[0m") # Red for errors (\033[91m)
                for d, err in trans['errors'].items():
                    link = links.get(d)
                    link_str = f" (See: {link})" if link else ""
                    print(f"    ❌ {d}: Error: {err}{link_str}")
            # Display details of records found on crt.sh
            if details:
                print("  \033[92mTransparency log records (crt.sh):\033[0m") # Green for records found (\033[92m)
                for d, records in details.items():
                    link = links.get(d)
                    link_str = f" (See: {link})" if link else ""
                    if records is not None:
                        count = len(records)
                        print(f"    ✅ {d}: {count} record(s){link_str}")
                    # Only show error here if it wasn't shown above
                    elif d not in trans.get('errors', {}):
                        print(
                            f"    ❓ {d}: No records found or error occurred{link_str}") # Yellow for unknown/error (\033[93m)

            # Display the total count of records found across all domains checked by crt.sh
            print(
                f"\n  \033[1mTotal records found across domains:\033[0m {total}")

    print(separator)
    print("\033[90m--- End of analysis ---\033[0m\n") # Grey for end message (\033[90m)


def create_parser():
    '''
    Create and configure the argument parser for check-tls.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    '''
    parser = argparse.ArgumentParser(
        description="Analyze TLS certificates for one or more domains.",
        epilog="Example: check-tls google.com example.org:8443 -j report.json"
    )
    parser.add_argument(
        '--version',
        '-V',
        action='version',
        version=f'%(prog)s {__version__}',
        help="Show program's version number and exit"
    )
    parser.add_argument('domains', nargs='*',
                        help='Domains to analyze (e.g., google.com or google.com:443)')
    parser.add_argument('-P', '--connect-port', type=int, default=443,
                        help='Port to connect to for TLS analysis (default: 443). This is overridden if port is specified in domain string e.g. example.com:1234')
    parser.add_argument('-j', '--json', type=str, metavar='FILE',
                        help='Output JSON report to FILE (use \"-\" for stdout)', default=None)
    parser.add_argument('-c', '--csv', type=str, metavar='FILE',
                        help='Output CSV report to FILE (use \"-\" for stdout)', default=None)
    parser.add_argument('-m', '--mode', type=str, choices=['simple', 'full'], default='full',
                        help="Analysis mode: 'simple' (leaf cert only) or 'full' (fetch intermediates, default: full)")
    parser.add_argument('-l', '--loglevel', type=str, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='WARNING',
                        help='Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)')
    parser.add_argument('-k', '--insecure', action='store_true',
                        help='Allow fetching certificates without validation (e.g., for self-signed certs)')
    parser.add_argument('-s', '--server', action='store_true',
                        help='Run as HTTP server with web interface')
    parser.add_argument('-p', '--port', type=int, default=8000,
                        help='Specify web server port (default: 8000)')
    parser.add_argument('--no-transparency', action='store_true',
                        help='Skip crt.sh certificate transparency check')
    parser.add_argument('--no-crl-check', action='store_true',
                        help='Disable CRL check for the leaf certificate')
    parser.add_argument('--no-ocsp-check', action='store_true',
                        help='Disable OCSP check for the leaf certificate')

    # Add shtab completion argument using the parser program name
    prog_name = parser.prog  # Get the program name (e.g., 'check-tls')
    shtab.add_argument_to(parser, ['--print-completion'], preamble={
        "bash": f"""
# Load this into your shell environment by adding
# eval "$({prog_name} --print-completion bash)"
# to your .bashrc or .bash_profile
        """,
        "zsh": f"""
# Load this into your shell environment by adding
# eval "$({prog_name} --print-completion zsh)"
# to your .zshrc
        """,
        "fish": f"""
# Save this script to ~/.config/fish/completions/{prog_name}.fish
# Or source it directly:
# {prog_name} --print-completion fish | source
        """
    })
    return parser


def main():
    """
    Main function to parse command-line arguments and execute TLS analysis,
    run the web server, or print shell completion scripts.
    """
    parser = create_parser()
    # shtab handles --print-completion here and exits if it's present
    args = parser.parse_args()

    # Configure logging only if we are not printing completion
    logging.basicConfig(
        level=get_log_level(args.loglevel),
        # Added logger name
        format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
    )
    # Use a specific logger for this module
    logger = logging.getLogger(__name__)

    # Check if action is required (domains analysis or server mode)
    # This check happens *after* shtab would have exited for completion.
    if not args.domains and not args.server:
        parser.print_help()
        sys.exit(0)

    # Run the web server if the --server flag is set
    if args.server:
        if args.domains:
            logger.warning(
                "Domains provided on the command line are ignored when running in server mode.")
        app = get_flask_app()
        run_server(args)

    # Perform TLS analysis for specified domains
    elif args.domains:
        # Process domains provided as arguments to extract host and port.
        # This handles inputs like 'google.com', 'google.com:443', or even URLs like 'https://google.com'.
        parsed_domains_for_analysis = []
        for domain_entry in args.domains:
            processed_entry = domain_entry
            # Prepend 'https://' if no scheme is present. This helps urlparse correctly handle host:port formats.
            if "://" not in processed_entry:
                parts_check = processed_entry.split(':', 1)
                # If a colon is present and the part after it is digits, assume it's host:port and prepend https://
                if len(parts_check) > 1 and parts_check[1].isdigit():
                    processed_entry = f"https://{processed_entry}"
                # If no colon is present, just prepend https://
                elif ':' not in processed_entry:
                    processed_entry = f"https://{processed_entry}"

            # Use urlparse to extract hostname and port
            parsed_url = urlparse(processed_entry)
            host = parsed_url.hostname
            port = parsed_url.port

            # If urlparse failed to extract a hostname (e.g., invalid format),
            # try to parse it manually as host[:port] and use the default port.
            if not host:
                logger.warning(
                    f"Could not extract hostname from '{domain_entry}'. Using entry as host and default port {args.connect_port}.")
                parts = domain_entry.split(':', 1)
                host = parts[0]
                port = args.connect_port # Start with default port
                if len(parts) > 1:
                    try:
                        # Attempt to parse port if provided manually
                        port_val = int(parts[1])
                        if 1 <= port_val <= 65535:
                            port = port_val # Use manual port if valid
                    except ValueError:
                        pass  # If manual port is not a valid integer, stick with default port

            # If port was not extracted by urlparse (e.g., no port specified in input), use the default port.
            if port is None:
                port = args.connect_port

            # Validate the final determined port number.
            if not (1 <= port <= 65535):
                logger.warning(
                    f"Port {port} for host {host} (from '{domain_entry}') is invalid. Using default/CLI port {args.connect_port}.")
                port = args.connect_port # Revert to default/CLI port if invalid

            # Append the processed host, port, and original entry to the list for analysis.
            parsed_domains_for_analysis.append(
                {'host': host, 'port': port, 'original_entry': domain_entry})

        # Determine output method: direct to console or to file (JSON/CSV).
        # If no JSON or CSV output file is specified, perform analysis and print summary directly.
        if not args.json and not args.csv:
            logger.info(
                f"Starting analysis for: {[item['original_entry'] for item in parsed_domains_for_analysis]}")
            results = []
            # Analyze each domain entry individually
            for item in parsed_domains_for_analysis:
                logger.debug(f"Analyzing {item['host']}:{item['port']}")
                results.append(
                    analyze_certificates(
                        domain=item['host'],
                        port=item['port'],
                        mode=args.mode,
                        insecure=args.insecure,
                        skip_transparency=args.no_transparency,
                        perform_crl_check=not args.no_crl_check,
                        perform_ocsp_check=not args.no_ocsp_check
                    )
                )
            # Print human-readable output directly to the console
            print_human_summary(results)
        # If JSON or CSV output is requested, call run_analysis which handles the analysis and file writing.
        else:
            # Call run_analysis which handles JSON/CSV output and runs analysis internally
            logger.info(
                f"Starting analysis for file output ({'JSON' if args.json else ''}{' and ' if args.json and args.csv else ''}{'CSV' if args.csv else ''}) for: {args.domains}")
            run_analysis(
                domains_input=args.domains,  # Pass original domain strings
                output_json=args.json,
                output_csv=args.csv,
                mode=args.mode,
                insecure=args.insecure,
                skip_transparency=args.no_transparency,
                perform_crl_check=not args.no_crl_check,
                perform_ocsp_check=not args.no_ocsp_check
            )


if __name__ == "__main__":
    main()
