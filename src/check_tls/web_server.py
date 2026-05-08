# Flask server and web interface
import logging
import argparse
import os # Added for path manipulation
from flask import Flask, render_template, request, jsonify, current_app
from check_tls.tls_checker import analyze_certificates
from check_tls.utils.domain_parser import parse_domain_entry
from markupsafe import Markup, escape


def get_tooltip(text):
    """
    Render a Bootstrap tooltip icon with HTML-escaped tooltip text.

    Uses ``Markup.format`` so the argument is auto-escaped by markupsafe,
    preventing XSS injection through the ``title`` attribute.

    Parameters
    ----------
    text : str
        The tooltip text to display on hover.  May contain arbitrary
        characters; they will be HTML-escaped before insertion.

    Returns
    -------
    Markup
        A ``Markup`` string containing the safe HTML for the tooltip icon.
    """
    return Markup(
        '<span data-bs-toggle="tooltip" data-bs-placement="top" title="{}">🛈</span>'
    ).format(escape(text))


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
    app.config['SCRIPT_ARGS'] = argparse.Namespace(insecure=False, no_transparency=False, no_crl_check=False, no_caa_check=False, connect_port=443)

    @app.after_request
    def _set_security_headers(response):
        """
        Attach security-related HTTP response headers to every response.

        Applied via ``after_request`` so the headers are present for both
        the HTML UI and the JSON API, and also when the app is served by a
        WSGI server instead of Flask's built-in server.

        Headers set (using ``setdefault`` so a downstream proxy can override):

        * ``X-Content-Type-Options: nosniff`` — prevents MIME-type sniffing.
        * ``X-Frame-Options: DENY`` — blocks clickjacking via iframes.
        * ``Referrer-Policy: no-referrer`` — suppresses the Referer header.
        * ``Content-Security-Policy`` — restricts resource loading:

          - Scripts: ``'self'`` + ``cdn.jsdelivr.net`` (Bootstrap bundle).
            ``'unsafe-inline'`` is **not** included because the HTML template
            contains no inline ``<script>`` blocks.
          - Styles: ``'self'`` + ``cdn.jsdelivr.net`` (Bootstrap CSS) +
            ``fonts.googleapis.com`` (Google Fonts CSS).  ``'unsafe-inline'``
            is kept because Bootstrap's JavaScript injects inline ``style``
            attributes at runtime (tooltip positioning, collapse, etc.).
          - Fonts: ``'self'`` + ``fonts.gstatic.com`` (Inter typeface files).
          - Images: ``'self' data:`` (Bootstrap uses data-URIs for some icons).
          - Frames: ``frame-ancestors 'none'`` — redundant with X-Frame-Options
            but respected by modern browsers.

        Parameters
        ----------
        response : flask.Response
            The outgoing Flask response object.

        Returns
        -------
        flask.Response
            The same response object with the security headers attached.
        """
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'",
        )
        return response

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
        no_caa_check_checked = script_args.no_caa_check
        # Use script_args.connect_port if available (though not directly set by current CLI for server mode)
        # or default to 443 for the form's initial display.
        connect_port_value = getattr(script_args, 'connect_port', 443)

        return render_template(
            'index.html',
            insecure_checked=insecure_checked,
            no_transparency_checked=no_transparency_checked,
            no_crl_check_checked=no_crl_check_checked,
            no_caa_check_checked=no_caa_check_checked,
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
        no_caa_check_flag = bool(data.get('no_caa_check', False))

        try:
            connect_port_from_json = int(data.get('connect_port', 443))
            if not (1 <= connect_port_from_json <= 65535):
                connect_port_from_json = 443
        except ValueError:
            connect_port_from_json = 443

        results = []
        for domain_entry in domains_input:
            parsed = parse_domain_entry(domain_entry, default_port=connect_port_from_json)
            analysis_result = analyze_certificates(
                domain=parsed.host,
                port=parsed.port,
                insecure=insecure_flag,
                skip_transparency=no_transparency_flag,
                perform_crl_check=not no_crl_check_flag,
                perform_ocsp_check=not no_ocsp_check_flag,
                perform_caa_check=not no_caa_check_flag
            )
            # Include OCSP results in JSON API
            analysis_result["ocsp_check"] = analysis_result.get("ocsp_check", {})
            analysis_result["caa_check"] = analysis_result.get("caa_check", {})
            results.append(analysis_result)
        return jsonify(results)
    return app


def run_server(args):
    """Run the Flask app behind Waitress on the given port (dual-stack IPv6 by default).

    For development/debug, set ``CHECK_TLS_DEV=1`` to fall back to Flask's
    built-in Werkzeug server with ``debug=True`` — convenient for live reload
    but **not** suitable for production use.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed command-line arguments.  Must contain at minimum:

        * ``port`` (int) — TCP port to listen on.

    Notes
    -----
    The production path uses ``waitress.serve`` with ``listen="*:PORT"``
    (Waitress wildcard) which binds to both IPv4 and IPv6 interfaces.
    ``threads=8`` provides basic concurrency without requiring an async
    runtime.  The ``ident`` parameter suppresses Waitress's default
    ``Server`` header so the implementation detail is not advertised.
    """
    logger = logging.getLogger(__name__)
    app = get_flask_app()

    if os.getenv("CHECK_TLS_DEV", "").lower() in {"1", "true", "yes"}:
        logger.warning(
            "CHECK_TLS_DEV is set — running Werkzeug dev server (NOT for production)."
        )
        app.run(host="::", port=args.port, debug=True)
        return

    from waitress import serve  # noqa: PLC0415 – intentional lazy import

    logger.info("Starting Waitress on http://*:%d (IPv4 + IPv6)", args.port)
    serve(app, listen=f"*:{args.port}", threads=8, ident="check-tls")
