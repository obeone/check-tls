# src/check_tls/utils/domain_parser.py
"""Shared domain-entry parser used by the CLI, REST API, and file-mode analysis."""

import logging
from dataclasses import dataclass
from urllib.parse import urlparse

logger = logging.getLogger("certcheck")

DEFAULT_PORT = 443


@dataclass(frozen=True)
class ParsedDomain:
    """Result of parsing a single domain entry.

    Attributes
    ----------
    host : str
        Extracted hostname (no brackets for IPv6 literals).
    port : int
        Port number in the 1–65535 range.
    original : str
        Verbatim input string, preserved for logging and error messages.
    """

    host: str
    port: int
    original: str


def parse_domain_entry(entry: str, default_port: int = DEFAULT_PORT) -> ParsedDomain:
    """Parse a domain entry into a (host, port) pair.

    Accepted input forms:

    * ``example.com``
    * ``example.com:8443``
    * ``https://example.com`` / ``https://example.com:9443/path``
    * ``[::1]:443`` (bracketed IPv6 literal with optional port)

    The function prepends ``https://`` when no scheme is present so that
    :func:`urllib.parse.urlparse` correctly splits host and port.  When the
    derived port is ``None`` or outside the 1–65535 range the ``default_port``
    is used instead.  If ``urlparse`` cannot extract a hostname at all the
    input is split on the first ``:`` and the left side is used as the host.

    Parameters
    ----------
    entry : str
        Raw domain string from CLI argument, JSON body, or domain-list file.
    default_port : int, optional
        Port to use when none can be determined from *entry*.
        Defaults to :data:`DEFAULT_PORT` (443).

    Returns
    -------
    ParsedDomain
        Immutable dataclass holding ``host``, ``port``, and ``original``.

    Examples
    --------
    >>> parse_domain_entry("example.com")
    ParsedDomain(host='example.com', port=443, original='example.com')
    >>> parse_domain_entry("example.com:8443")
    ParsedDomain(host='example.com', port=8443, original='example.com:8443')
    >>> parse_domain_entry("https://example.com:9443/path")
    ParsedDomain(host='example.com', port=9443, original='https://example.com:9443/path')
    """
    processed = entry

    # Prepend https:// so urlparse can split host:port unambiguously.
    if "://" not in processed:
        parts_check = processed.split(":", 1)
        if len(parts_check) > 1 and parts_check[1].isdigit():
            # Looks like host:port — add scheme.
            processed = f"https://{processed}"
        elif ":" not in processed:
            # Plain hostname — add scheme.
            processed = f"https://{processed}"
        # else: contains a colon but the right side is not purely digits
        # (e.g. IPv6 without brackets, or garbage).  urlparse will handle it.

    parsed_url = urlparse(processed)
    host = parsed_url.hostname  # None when urlparse cannot split
    port = parsed_url.port      # None when no port in URL

    if not host:
        # urlparse gave up — fall back to a simple split on first colon.
        logger.warning(
            "Could not extract hostname from '%s' via urlparse; "
            "falling back to split-on-colon.",
            entry,
        )
        parts = entry.split(":", 1)
        host = parts[0]
        port = default_port
        if len(parts) > 1:
            try:
                port_val = int(parts[1])
                if 1 <= port_val <= 65535:
                    port = port_val
            except ValueError:
                pass  # leave port = default_port

    # port is None when the URL had no explicit port.
    if port is None:
        port = default_port

    # Clamp out-of-range ports to the default.
    if not (1 <= port <= 65535):
        logger.warning(
            "Port %d for host '%s' (from '%s') is out of range 1-65535; "
            "using default port %d.",
            port,
            host,
            entry,
            default_port,
        )
        port = default_port

    return ParsedDomain(host=host, port=port, original=entry)
