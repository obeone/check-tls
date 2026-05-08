"""
hsts_utils.py
=============

HTTP Strict Transport Security (HSTS) inspection utilities.

Provides :func:`check_hsts` which performs an HTTPS ``HEAD`` request to a
domain via :func:`safe_http_fetch` (so SSRF protection is honored) and
returns a parsed view of the ``Strict-Transport-Security`` response
header per RFC 6797.
"""

from typing import Any, Dict, Optional

from check_tls.utils.security_utils import safe_http_fetch


def _parse_hsts_header(header_value: str) -> Dict[str, Any]:
    """
    Parse a ``Strict-Transport-Security`` header value per RFC 6797.

    Directive names are matched case-insensitively. Values may be
    quoted (``max-age="31536000"``) and surrounding whitespace is
    tolerated.

    Parameters
    ----------
    header_value : str
        The raw header value (without the field name).

    Returns
    -------
    Dict[str, Any]
        Parsed values with keys:

        - ``max_age`` (Optional[int])
        - ``include_subdomains`` (bool)
        - ``preload`` (bool)
    """
    parsed: Dict[str, Any] = {
        "max_age": None,
        "include_subdomains": False,
        "preload": False,
    }

    for raw_directive in header_value.split(";"):
        directive = raw_directive.strip()
        if not directive:
            continue
        if "=" in directive:
            name, _, value = directive.partition("=")
            name = name.strip().lower()
            value = value.strip().strip('"').strip("'")
            if name == "max-age":
                try:
                    parsed["max_age"] = int(value)
                except ValueError:
                    parsed["max_age"] = None
        else:
            name = directive.lower()
            if name == "includesubdomains":
                parsed["include_subdomains"] = True
            elif name == "preload":
                parsed["preload"] = True

    return parsed


def check_hsts(domain: str, port: int = 443) -> Dict[str, Any]:
    """
    Probe a domain for an HTTP Strict Transport Security policy.

    Issues an HTTPS ``HEAD`` request to ``https://<domain>:<port>/``
    via :func:`safe_http_fetch` (which enforces SSRF protections and
    re-validates each redirect hop) and inspects the
    ``Strict-Transport-Security`` response header.

    Parameters
    ----------
    domain : str
        Hostname to probe.
    port : int, optional
        TCP port to use in the HTTPS URL. Defaults to ``443``.

    Returns
    -------
    Dict[str, Any]
        A dictionary with the following keys:

        - ``checked`` (bool): always ``True`` — this function ran.
        - ``header_present`` (bool): ``True`` when an HSTS header
          was returned by the server.
        - ``max_age`` (Optional[int]): parsed ``max-age`` directive.
        - ``include_subdomains`` (bool): ``True`` when
          ``includeSubDomains`` is set.
        - ``preload`` (bool): ``True`` when ``preload`` is set.
        - ``raw_header`` (Optional[str]): the unparsed header value.
        - ``error`` (Optional[str]): non-``None`` when the HEAD
          request could not be performed.

    Examples
    --------
    >>> result = check_hsts("example.com")  # doctest: +SKIP
    >>> result["header_present"]
    True
    """
    result: Dict[str, Any] = {
        "checked": True,
        "header_present": False,
        "max_age": None,
        "include_subdomains": False,
        "preload": False,
        "raw_header": None,
        "error": None,
    }

    # Build the target URL. Omit the explicit port when 443 to avoid
    # confusing servers that vary content based on Host header.
    if port == 443:
        url = f"https://{domain}/"
    else:
        url = f"https://{domain}:{port}/"

    response = safe_http_fetch(url, method="HEAD")
    if response is None:
        result["error"] = (
            "HSTS check failed: HEAD request was rejected, errored out, "
            "or returned a non-success status."
        )
        return result

    header_value: Optional[str] = response.headers.get("Strict-Transport-Security")
    if not header_value:
        return result

    result["header_present"] = True
    result["raw_header"] = header_value

    parsed = _parse_hsts_header(header_value)
    result["max_age"] = parsed["max_age"]
    result["include_subdomains"] = parsed["include_subdomains"]
    result["preload"] = parsed["preload"]

    return result
