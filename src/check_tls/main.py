# src/check_tls/main.py

import argparse
import logging
import sys
import shtab  # Import shtab
from urllib.parse import urlparse
from check_tls import __version__
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
        cert_count_color = '\033[92m' if certs_list else '\033[91m'
        print(
            f"\n\033[1mCertificate Chain Details:\033[0m ({cert_count_color}{len(certs_list)} found\033[0m)")
        if not certs_list and result.get('status') != 'failed':
            print(
                "  \033[93m⚠️ No certificates were processed successfully.\033[0m")
        for cert in certs_list:
            chain_index = cert.get('chain_index', '?')

            if chain_index == 0:
                chain_emoji = "🔒"  # Leaf certificate
            elif isinstance(chain_index, int) and chain_index == len(certs_list) - 1:
                chain_emoji = "🏁"  # Root certificate (assuming last is root)
            else:
                chain_emoji = "🔗"  # Intermediate certificate

            if 'error' in cert:
                print(
                    f"  [{chain_emoji} Chain Index {chain_index}] \033[91m\033[1m❌ Error: {cert['error']}\033[0m")
                continue

            print(
                f"  [{chain_emoji} Chain Index {chain_index}] \033[1mSubject:\033[0m \033[96m{cert.get('subject', 'N/A')}\033[0m")
            print(
                f"      \033[1mIssuer:\033[0m \033[94m{cert.get('issuer', 'N/A')}\033[0m")
            print(
                f"      \033[1mSerial:\033[0m {cert.get('serial_number', 'N/A')} | \033[1mProfile:\033[0m {cert.get('profile', 'N/A')}")

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

            pub_key_algo = cert.get('public_key_algorithm', 'N/A')
            pub_key_size = cert.get('public_key_size_bits', 'N/A')
            print(
                f"      \033[1mPublic Key:\033[0m {pub_key_algo} (\033[1m{pub_key_size} bits\033[0m)")
            print(
                f"      \033[1mSignature:\033[0m {cert.get('signature_algorithm', 'N/A')}")
            print(
                f"      \033[1mSHA256 FP:\033[0m {cert.get('sha256_fingerprint', 'N/A')}")

            sans = cert.get('san', [])
            if sans:
                max_sans_display = 5
                sans_display = ', '.join(sans[:max_sans_display])
                if len(sans) > max_sans_display:
                    sans_display += f", ... (\033[90m{len(sans) - max_sans_display} more\033[0m)"
                print(f"      \033[1mSANs:\033[0m {sans_display}")
            else:
                print(f"      \033[1mSANs:\033[0m None")

            print("")  # Extra newline for readability between certs

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
                print("  \033[91mErrors found during crt.sh query:\033[0m")
                for d, err in trans['errors'].items():
                    link = links.get(d)
                    link_str = f" (See: {link})" if link else ""
                    print(f"    ❌ {d}: Error: {err}{link_str}")
            if details:
                print("  \033[92mTransparency log records (crt.sh):\033[0m")
                for d, records in details.items():
                    link = links.get(d)
                    link_str = f" (See: {link})" if link else ""
                    if records is not None:
                        count = len(records)
                        print(f"    ✅ {d}: {count} record(s){link_str}")
                    # Only show error here if it wasn't shown above
                    elif d not in trans.get('errors', {}):
                        print(
                            f"    ❓ {d}: No records found or error occurred{link_str}")

            print(
                f"\n  \033[1mTotal records found across domains:\033[0m {total}")

    print(separator)
    print("\033[90m--- End of analysis ---\033[0m\n")


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
        # Pass all parsed args to the server function
        run_server(args)

    # Perform TLS analysis for specified domains
    elif args.domains:
        # Process domains to extract host and port
        parsed_domains_for_analysis = []
        for domain_entry in args.domains:
            processed_entry = domain_entry
            if "://" not in processed_entry:
                parts_check = processed_entry.split(':', 1)
                if len(parts_check) > 1 and parts_check[1].isdigit():
                    processed_entry = f"https://{processed_entry}"
                elif ':' not in processed_entry:
                    processed_entry = f"https://{processed_entry}"

            parsed_url = urlparse(processed_entry)
            host = parsed_url.hostname
            port = parsed_url.port

            if not host:
                logger.warning(
                    f"Could not extract hostname from '{domain_entry}'. Using entry as host and default port {args.connect_port}.")
                parts = domain_entry.split(':', 1)
                host = parts[0]
                port = args.connect_port
                if len(parts) > 1:
                    try:
                        port_val = int(parts[1])
                        if 1 <= port_val <= 65535:
                            port = port_val
                    except ValueError:
                        pass  # Use default port

            if port is None:
                port = args.connect_port

            if not (1 <= port <= 65535):
                logger.warning(
                    f"Port {port} for host {host} (from '{domain_entry}') is invalid. Using default/CLI port {args.connect_port}.")
                port = args.connect_port

            parsed_domains_for_analysis.append(
                {'host': host, 'port': port, 'original_entry': domain_entry})

        # Perform the analysis directly here if not outputting to file
        # If outputting to file, run_analysis will handle it
        if not args.json and not args.csv:
            logger.info(
                f"Starting analysis for: {[item['original_entry'] for item in parsed_domains_for_analysis]}")
            results = []
            for item in parsed_domains_for_analysis:
                logger.debug(f"Analyzing {item['host']}:{item['port']}")
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
            # Print human-readable output directly
            print_human_summary(results)
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
                perform_crl_check=not args.no_crl_check
            )


if __name__ == "__main__":
    main()
