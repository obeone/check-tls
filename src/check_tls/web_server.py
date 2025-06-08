# Flask server and web interface
import logging
import argparse
import os # Added for path manipulation
from urllib.parse import urlparse  # Added for URL parsing
from flask import Flask, render_template, request, jsonify, current_app
from check_tls.tls_checker import analyze_certificates
from markupsafe import Markup


def get_tooltip(text):
    """
    Generate a Bootstrap tooltip icon with the given text.

    Args:
        text (str): The tooltip text to display on hover.

    Returns:
        Markup: A Markup string containing the HTML for the tooltip icon.
    """
    return Markup(f"<span data-bs-toggle='tooltip' data-bs-placement='top' title='{text}'>🛈</span>")


def get_flask_app():
    """
    Create and return a Flask app instance for WSGI servers.

    This function provides a Flask app instance with similar configuration
    as run_server, suitable for deployment with WSGI servers like waitress.

    Returns:
        Flask: Configured Flask application instance.
    """
    # Determine the absolute path to the project's root directory to correctly locate templates and static files.
    # __file__ gives the path to the current file (web_server.py)
    # os.path.dirname(__file__) gives the directory of the current file (src/check_tls)
    # os.path.join(os.path.dirname(__file__), '..', '..') navigates two levels up to the project root
    project_root = os.path.dirname(__file__)
    app = Flask(__name__,
                template_folder=os.path.join(project_root, 'templates'),
                static_folder=os.path.join(project_root, 'static'))
    app.config['SCRIPT_ARGS'] = argparse.Namespace(insecure=False, no_transparency=False, no_crl_check=False, connect_port=443)

    @app.route('/', methods=['GET'])
    def index():
        """
        Handle the main page requests for TLS analysis.

        GET: Render the input form.

        Returns:
            str or Response: Rendered HTML page with results.
        """
        script_args = app.config['SCRIPT_ARGS']

        # Preserve checkbox states from script arguments for initial form rendering
        insecure_checked = script_args.insecure
        no_transparency_checked = script_args.no_transparency
        no_crl_check_checked = script_args.no_crl_check
        # Use script_args.connect_port if available (though not directly set by current CLI for server mode)
        # or default to 443 for the form's initial display.
        connect_port_value = getattr(script_args, 'connect_port', 443)

        return render_template(
            'index.html',
            insecure_checked=insecure_checked,
            no_transparency_checked=no_transparency_checked,
            no_crl_check_checked=no_crl_check_checked,
            connect_port_value=connect_port_value,
            get_tooltip=get_tooltip
        )

    @app.route('/api/analyze', methods=['POST'])
    def api_analyze():
        """
        API endpoint to analyze TLS certificates for a list of domains.

        Expects a JSON body with a "domains" list and optional flags:
        - insecure (bool)
        - no_transparency (bool)
        - no_crl_check (bool)
        - no_ocsp_check (bool)
        - connect_port (int, optional, default: 443)

        Returns:
            JSON response with analysis results or error message.
        """
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400

        data = request.get_json()
        domains_input = data.get('domains')

        if not domains_input or not isinstance(domains_input, list):
            return jsonify({'error': 'JSON body must contain a list of domains under "domains"'}), 400

        insecure_flag = bool(data.get('insecure', False))
        no_transparency_flag = bool(data.get('no_transparency', False))
        no_crl_check_flag = bool(data.get('no_crl_check', False))
        no_ocsp_check_flag = bool(data.get('no_ocsp_check', False))

        try:
            connect_port_from_json = int(data.get('connect_port', 443))
            if not (1 <= connect_port_from_json <= 65535):
                connect_port_from_json = 443
        except ValueError:
            connect_port_from_json = 443

        results = []
        for domain_entry in domains_input:
            processed_entry = domain_entry
            if "://" not in processed_entry:
                parts_check = processed_entry.split(':', 1)
                if len(parts_check) > 1 and parts_check[1].isdigit():
                     processed_entry = f"https://{processed_entry}"
                elif ':' not in processed_entry:
                    processed_entry = f"https://{processed_entry}"

            parsed_url = urlparse(processed_entry)
            host = parsed_url.hostname
            port_in_domain = parsed_url.port

            if not host:
                current_app.logger.warning(f"API: Could not extract hostname from '{domain_entry}'. Using entry as host.")
                host = domain_entry.split(':')[0]  # Basic fallback
                port_to_use = connect_port_from_json
            else:
                port_to_use = port_in_domain if port_in_domain else connect_port_from_json

            if not (1 <= port_to_use <= 65535):
                current_app.logger.warning(f"API: Port {port_to_use} for host {host} (from '{domain_entry}') is invalid. Using default {connect_port_from_json}.")
                port_to_use = connect_port_from_json

            analysis_result = analyze_certificates(
                domain=host,
                port=port_to_use,
                insecure=insecure_flag,
                skip_transparency=no_transparency_flag,
                perform_crl_check=not no_crl_check_flag,
                perform_ocsp_check=not no_ocsp_check_flag
            )
            # Include OCSP results in JSON API
            analysis_result["ocsp_check"] = analysis_result.get("ocsp_check", {})
            results.append(analysis_result)
        return jsonify(results)
    return app


def run_server(args):
    """
    Run the Flask web server for interactive TLS analysis.

    This function initializes the Flask application, sets up routes for the
    web interface and API, and starts the server on the specified port.

    Args:
        args (argparse.Namespace): Parsed command-line arguments containing
            configuration options such as the port number and flags for
            insecure connections, transparency checks, and CRL checks.

    Routes:
        '/' (GET): Main page for domain input and displaying results.
        '/api/analyze' (POST): API endpoint for JSON-based domain analysis.

    The web interface supports form submission with domain names and options,
    and returns analysis results rendered in HTML or JSON format based on the
    Accept header.
    """
    logging.info(f"Starting Flask server on http://0.0.0.0:{args.port}")
    try:
        app = get_flask_app()
        app.run(host='0.0.0.0', port=args.port, debug=False)
    except Exception as e:
        logging.error(f"Failed to start Flask server: {e}")
