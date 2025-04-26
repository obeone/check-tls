  # CLI entry point and argument parsing
import argparse
import logging
from check_tls.tls_checker import run_analysis, analyze_certificates, get_log_level
from check_tls.web_server import run_server

def print_human_summary(results):
    for result in results:
        print("\n\033[1m=== TLS Analysis for domain: {} ===\033[0m".format(result.get('domain', 'N/A')))
        print(f"Status: {result.get('status', 'N/A')}")
        if result.get('error_message'):
            print(f"Error: \033[91m{result['error_message']}\033[0m")
        conn = result.get('connection_health', {})
        print("\n  \033[1mConnection Health:\033[0m")
        if not conn.get('checked'):
            print("    Status      : \033[93mNot Checked / Failed\033[0m")
        else:
            print(f"    TLS Version : {conn.get('tls_version', 'N/A')}")
            tls13_support = conn.get('supports_tls13')
            tls13_text = '\033[92mYes\033[0m' if tls13_support is True else ('\033[91mNo\033[0m' if tls13_support is False else '\033[93mN/A\033[0m')
            print(f"    TLS 1.3     : {tls13_text}")
            print(f"    Cipher Suite: {conn.get('cipher_suite', 'N/A')}")
            if conn.get('error'):
                print(f"    Error       : \033[91m{conn['error']}\033[0m")
        val = result.get('validation', {})
        sys_val = val.get('system_trust_store')
        val_status = sys_val
        print("\n  \033[1mCertificate Validation:\033[0m")
        if val_status is True:
            val_text = '\033[92m✔️ Valid (System Trust)\033[0m'
        elif val_status is False:
            val_text = f'\033[91m❌ Invalid (System Trust)'
            if val.get('error'):
                val_text += f" ({val['error']})"
            val_text += '\033[0m'
        elif val.get('error'):
            val_text = f"\033[91m❌ Error ({val['error']})\033[0m"
        else:
            val_text = "\033[93m❓ Unknown/Skipped\033[0m"
        print(f"    {val_text}")
        certs_list = result.get('certificates', [])
        leaf_cert_data = certs_list[0] if certs_list and 'error' not in certs_list[0] else None
        if leaf_cert_data:
            print("\n  \033[1mLeaf Certificate Summary:\033[0m")
            print(f"    Common Name: \033[96m{leaf_cert_data.get('common_name', 'N/A')}\033[0m")
            days_left_leaf = leaf_cert_data.get('days_remaining', None)
            expiry_text_leaf = leaf_cert_data.get('not_after', 'N/A')
            if days_left_leaf is not None:
                expiry_color_leaf = '\033[91m' if days_left_leaf < 30 else ('\033[93m' if days_left_leaf < 90 else '\033[92m')
                expiry_text_leaf += f" ({expiry_color_leaf}{days_left_leaf} days remaining\033[0m)"
            else:
                expiry_text_leaf += " (\033[93mExpiry N/A\033[0m)"
            print(f"    Expires    : {expiry_text_leaf}")
            sans_leaf = leaf_cert_data.get('san', [])
            max_sans_display = 5
            sans_display = ', '.join(sans_leaf[:max_sans_display])
            if len(sans_leaf) > max_sans_display:
                sans_display += f", ... ({len(sans_leaf) - max_sans_display} more)"
            print(f"    SANs       : {sans_display if sans_leaf else 'None'}")
            print(f"    Issuer     : {leaf_cert_data.get('issuer', 'N/A')}")
        print("\n  \033[1mCRL Check (Leaf):\033[0m")
        crl_check_data = result.get('crl_check', {})
        if not crl_check_data.get('checked'):
            print("    Status      : \033[93mSkipped\033[0m")
        else:
            crl_status = crl_check_data.get('leaf_status', 'error')
            crl_details = crl_check_data.get('details', {})
            crl_reason = crl_details.get('reason', 'No details available.') if isinstance(crl_details, dict) else 'Invalid details format.'
            crl_uri = crl_details.get('checked_uri') if isinstance(crl_details, dict) else None
            status_map = {"good": "\033[92m✔️ Good\033[0m", "revoked": "\033[91m❌ REVOKED\033[0m", "crl_expired": "\033[93m⚠️ CRL Expired\033[0m", "unreachable": "\033[93m⚠️ Unreachable\033[0m", "parse_error": "\033[91m❌ Parse Error\033[0m", "no_cdp": "\033[94mℹ️ No CDP\033[0m", "no_http_cdp": "\033[94mℹ️ No HTTP CDP\033[0m", "error": "\033[91m❌ Error\033[0m"}
            status_text = status_map.get(crl_status, "\033[93m❓ Unknown\033[0m")
            print(f"    Status      : {status_text}")
            print(f"    Detail      : {crl_reason}")
            if crl_uri:
                print(f"    Checked URI : {crl_uri}")
        cert_count_color = '\033[92m' if certs_list else '\033[91m'
        print(f"\n  \033[1mCertificate Chain Details:\033[0m ({cert_count_color}{len(certs_list)} found\033[0m)")
        if not certs_list and result.get('status') != 'failed':
            print("    \033[93mNo certificates were processed successfully.\033[0m")
        for cert in certs_list:
            if 'error' in cert:
                print(f"    [Chain Index {cert.get('chain_index', '?')}] \033[91mError: {cert['error']}\033[0m")
            else:
                print(f"    [Chain Index {cert.get('chain_index', '?')}] Subject: {cert.get('subject', 'N/A')}")
                print(f"        Issuer: {cert.get('issuer', 'N/A')}")
                print(f"        Serial: {cert.get('serial_number', 'N/A')} | Profile: {cert.get('profile', 'N/A')}")
                print(f"        Valid: {cert.get('not_before', 'N/A')} -> {cert.get('not_after', 'N/A')} | {cert.get('days_remaining', 'N/A')} days left")
                print(f"        Public Key: {cert.get('public_key_algorithm', 'N/A')} ({cert.get('public_key_size_bits', 'N/A')} bits)")
                print(f"        Signature: {cert.get('signature_algorithm', 'N/A')}")
                print(f"        SHA256 Fingerprint: {cert.get('sha256_fingerprint', 'N/A')}")
                print(f"        SANs: {', '.join(cert.get('san', [])) if cert.get('san') else 'None'}\n")
        # Certificate Transparency
        trans = result.get('transparency', {})
        print("\n  \033[1mCertificate Transparency:\033[0m")
        if not trans.get('checked'):
            print("    Status: \033[93mSkipped\033[0m")
        else:
            details = trans.get('details', {})
            links = trans.get('crtsh_report_links', {})
            total = trans.get('crtsh_records_found', 0)
            if trans.get('errors'):
                for d, err in trans['errors'].items():
                    link = links.get(d)
                    print(f"    {d}: \033[91mError: {err}\033[0m" + (f" [crt.sh]({link})" if link else ""))
            else:
                for d, records in details.items():
                    link = links.get(d)
                    count = len(records) if records is not None else 'Error'
                    print(f"    {d}: {count} record(s)" + (f" [crt.sh]({link})" if link else ""))
            print(f"    Total records found: {total}")
    print("\n\033[90m--- End of analysis ---\033[0m\n")

def main():
    parser = argparse.ArgumentParser(description="Analyze TLS certificates for one or more domains.")
    parser.add_argument('domains', nargs='*', help='Domains to analyze')
    parser.add_argument('-j', '--json', type=str, help='Output JSON report to FILE (use "-" for stdout)', default=None)
    parser.add_argument('-c', '--csv', type=str, help='Output CSV report to FILE (use "-" for stdout)', default=None)
    parser.add_argument('-m', '--mode', type=str, choices=['simple', 'full'], default='full', help="Choose mode: 'simple' or 'full' (default: full)")
    parser.add_argument('-l', '--loglevel', type=str, default='WARNING', help='Set log level (default: WARN)')
    parser.add_argument('-k', '--insecure', action='store_true', help='Allow fetching certificates without validation (self-signed)')
    parser.add_argument('-s', '--server', action='store_true', help='Run as HTTP server with web interface')
    parser.add_argument('-p', '--port', type=int, default=8000, help='Specify server port (default: 8000)')
    parser.add_argument('--no-transparency', action='store_true', help='Skip crt.sh certificate transparency check')
    parser.add_argument('--no-crl-check', action='store_true', help='Disable CRL check for the leaf certificate (experimental)')
    args = parser.parse_args()

    logging.basicConfig(level=get_log_level(args.loglevel))

    if not args.domains and not args.server:
        parser.print_help()
        return

    if args.server:
        run_server(args)
    else:
        if args.domains:
            results = [analyze_certificates(domain, mode=args.mode, insecure=args.insecure, skip_transparency=args.no_transparency, perform_crl_check=not args.no_crl_check) for domain in args.domains]
            if args.json or args.csv:
                run_analysis(
                    domains=args.domains,
                    output_json=args.json,
                    output_csv=args.csv,
                    mode=args.mode,
                    insecure=args.insecure,
                    skip_transparency=args.no_transparency,
                    perform_crl_check=not args.no_crl_check
                )
            else:
                print_human_summary(results)
        else:
            parser.print_help()

if __name__ == "__main__":
    main()
