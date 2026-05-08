"""Tests for web_server hardening: tooltip XSS escaping and security headers."""
import pytest
from markupsafe import Markup
from check_tls.web_server import get_tooltip, get_flask_app


# ---------------------------------------------------------------------------
# get_tooltip – XSS escaping
# ---------------------------------------------------------------------------

class TestGetTooltip:
    """Verify that get_tooltip safely escapes its argument."""

    def test_returns_markup_instance(self):
        """Return value must be a Markup so Jinja2 won't double-escape it."""
        result = get_tooltip("hello")
        assert isinstance(result, Markup)

    def test_plain_text_round_trips(self):
        """Plain ASCII text should appear unchanged inside the title attribute."""
        result = get_tooltip("some text")
        assert 'title="some text"' in result

    def test_script_tag_escaped(self):
        """
        A ``<script>`` payload must be HTML-escaped so it cannot execute.

        Passing ``'<script>alert(1)</script>'`` must produce ``&lt;script&gt;``
        in the rendered output, never a raw ``<script>`` tag.
        """
        payload = "<script>alert(1)</script>"
        result = get_tooltip(payload)
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_quote_injection_escaped(self):
        """
        A payload designed to break out of the title attribute must be escaped.

        ``'" onload="x'`` would close the attribute and inject an event handler
        if not properly escaped.  The double-quote must appear as ``&#34;`` or
        ``&quot;`` — never as a raw ``"`` that could terminate the attribute.
        """
        payload = '" onload="x'
        result = get_tooltip(payload)
        # The rendered title="..." must not contain an unescaped closing quote
        # that would allow attribute break-out.  markupsafe escapes " as &#34;.
        assert '" onload="' not in result
        # The escaped form should be present somewhere in the output.
        assert "&#34;" in result or "&quot;" in result

    def test_ampersand_escaped(self):
        """Ampersands must be escaped to ``&amp;``."""
        result = get_tooltip("a & b")
        assert "&amp;" in result
        # Raw unescaped ampersand must not appear inside the attribute value
        assert "title=\"a & b\"" not in result


# ---------------------------------------------------------------------------
# Security headers – HTML page
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def flask_client():
    """Provide a Flask test client for the full app."""
    app = get_flask_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestSecurityHeadersOnIndex:
    """Security headers must be present on GET /."""

    def test_x_content_type_options(self, flask_client):
        """X-Content-Type-Options must be 'nosniff'."""
        response = flask_client.get("/")
        assert response.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options(self, flask_client):
        """X-Frame-Options must be 'DENY'."""
        response = flask_client.get("/")
        assert response.headers.get("X-Frame-Options") == "DENY"

    def test_referrer_policy(self, flask_client):
        """Referrer-Policy must be 'no-referrer'."""
        response = flask_client.get("/")
        assert response.headers.get("Referrer-Policy") == "no-referrer"

    def test_content_security_policy_present(self, flask_client):
        """Content-Security-Policy header must be set."""
        response = flask_client.get("/")
        csp = response.headers.get("Content-Security-Policy", "")
        assert csp, "Content-Security-Policy header is missing"

    def test_csp_contains_default_src_self(self, flask_client):
        """CSP must include a default-src directive."""
        response = flask_client.get("/")
        csp = response.headers.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp

    def test_csp_contains_frame_ancestors_none(self, flask_client):
        """CSP must include frame-ancestors 'none' to block framing."""
        response = flask_client.get("/")
        csp = response.headers.get("Content-Security-Policy", "")
        assert "frame-ancestors 'none'" in csp


# ---------------------------------------------------------------------------
# Security headers – API error response
# ---------------------------------------------------------------------------

class TestSecurityHeadersOnApiError:
    """Security headers must also be present on API error responses."""

    def test_headers_on_non_json_request(self, flask_client):
        """
        POST /api/analyze with non-JSON body returns 400 but must still carry
        all four security headers.
        """
        response = flask_client.post(
            "/api/analyze",
            data="not json",
            content_type="text/plain",
        )
        assert response.status_code == 400
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert response.headers.get("Referrer-Policy") == "no-referrer"
        assert response.headers.get("Content-Security-Policy")

    def test_headers_on_missing_domains_field(self, flask_client):
        """
        POST /api/analyze with JSON body lacking 'domains' returns 400 but
        must still carry all four security headers.
        """
        response = flask_client.post(
            "/api/analyze",
            json={},
        )
        assert response.status_code == 400
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert response.headers.get("Referrer-Policy") == "no-referrer"
        assert response.headers.get("Content-Security-Policy")
