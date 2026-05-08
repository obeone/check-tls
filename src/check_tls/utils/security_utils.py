"""
security_utils.py

Security validation utilities for preventing SSRF and other attacks.
Provides functions to validate domains and IP addresses before making connections.
"""

import ipaddress
import os
import socket
import logging
from typing import Tuple, Optional, Dict
from urllib.parse import urljoin, urlparse

import requests


# Private/internal IP ranges that should be blocked to prevent SSRF attacks
BLOCKED_IP_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),       # RFC1918 - Private network
    ipaddress.ip_network('172.16.0.0/12'),    # RFC1918 - Private network
    ipaddress.ip_network('192.168.0.0/16'),   # RFC1918 - Private network
    ipaddress.ip_network('127.0.0.0/8'),      # RFC1122 - Loopback
    ipaddress.ip_network('169.254.0.0/16'),   # RFC3927 - Link-local
    ipaddress.ip_network('0.0.0.0/8'),        # RFC1122 - Current network
    ipaddress.ip_network('100.64.0.0/10'),    # RFC6598 - Shared address space
    ipaddress.ip_network('192.0.0.0/24'),     # RFC6890 - IETF protocol assignments
    ipaddress.ip_network('192.0.2.0/24'),     # RFC5737 - Documentation
    ipaddress.ip_network('198.18.0.0/15'),    # RFC2544 - Benchmarking
    ipaddress.ip_network('198.51.100.0/24'),  # RFC5737 - Documentation
    ipaddress.ip_network('203.0.113.0/24'),   # RFC5737 - Documentation
    ipaddress.ip_network('224.0.0.0/4'),      # RFC5771 - Multicast
    ipaddress.ip_network('240.0.0.0/4'),      # RFC1112 - Reserved
    ipaddress.ip_network('255.255.255.255/32'), # RFC919 - Broadcast
    # IPv6 ranges
    ipaddress.ip_network('::1/128'),          # RFC4291 - Loopback
    ipaddress.ip_network('fe80::/10'),        # RFC4291 - Link-local
    ipaddress.ip_network('fc00::/7'),         # RFC4193 - Unique local address
    ipaddress.ip_network('ff00::/8'),         # RFC4291 - Multicast
    ipaddress.ip_network('::ffff:0:0/96'),    # RFC4291 - IPv4-mapped IPv6
    ipaddress.ip_network('2001:db8::/32'),    # RFC3849 - Documentation
]


def is_ip_blocked(ip_address_str: str) -> Tuple[bool, Optional[str]]:
    """
    Check if an IP address is in a blocked range (private/internal networks).

    Args:
        ip_address_str (str): The IP address to check as a string.

    Returns:
        Tuple[bool, Optional[str]]:
            - True if the IP is blocked, False otherwise
            - Error message if blocked, None otherwise

    Example:
        >>> is_ip_blocked('192.168.1.1')
        (True, 'IP address 192.168.1.1 is in blocked range 192.168.0.0/16 (Private network)')
        >>> is_ip_blocked('8.8.8.8')
        (False, None)
    """
    try:
        ip = ipaddress.ip_address(ip_address_str)
        for network in BLOCKED_IP_RANGES:
            if ip in network:
                return True, f"IP address {ip_address_str} is in blocked range {network} (Private/internal network)"
        return False, None
    except ValueError as e:
        # Not a valid IP address
        return False, None


def validate_host_for_connection(host: str, port: int, allow_private_ips: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Validate a host before making a connection to prevent SSRF attacks.

    This function checks if the host (domain or IP) resolves to a private/internal
    IP address that could be exploited for SSRF attacks.

    Args:
        host (str): The hostname or IP address to validate.
        port (int): The port number (for logging purposes).
        allow_private_ips (bool): If True, allow connections to private IPs.
                                  Defaults to False for security.

    Returns:
        Tuple[bool, Optional[str]]:
            - True if validation passed (host is safe to connect to)
            - Error message if validation failed, None otherwise

    Example:
        >>> validate_host_for_connection('example.com', 443)
        (True, None)
        >>> validate_host_for_connection('192.168.1.1', 443)
        (False, 'Blocked connection to private IP...')
    """
    logger = logging.getLogger("certcheck")

    # If private IPs are explicitly allowed, skip validation
    if allow_private_ips:
        logger.debug(f"Allowing connection to {host}:{port} (private IPs allowed)")
        return True, None

    # Check if host is already an IP address
    try:
        ip = ipaddress.ip_address(host)
        is_blocked, block_msg = is_ip_blocked(str(ip))
        if is_blocked:
            error_msg = f"Blocked connection to private/internal IP: {block_msg}"
            logger.warning(error_msg)
            return False, error_msg
        # IP is public, allow connection
        return True, None
    except ValueError:
        # Not an IP address, it's a hostname - need to resolve it
        pass

    # Resolve hostname to IP address(es) and check each one
    try:
        resolved_ips = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for result in resolved_ips:
            family, socktype, proto, canonname, sockaddr = result
            ip_str = sockaddr[0]  # Extract IP address

            is_blocked, block_msg = is_ip_blocked(ip_str)
            if is_blocked:
                error_msg = f"Blocked connection to {host}:{port} - resolves to private/internal IP: {block_msg}"
                logger.warning(error_msg)
                return False, error_msg

        # All resolved IPs are public, allow connection
        logger.debug(f"Validated {host}:{port} - resolves to public IPs only")
        return True, None

    except socket.gaierror as e:
        # DNS resolution failed - let the connection attempt handle this error
        logger.debug(f"DNS resolution failed for {host}: {e}")
        return True, None  # Allow the connection to proceed and fail naturally with proper error
    except Exception as e:
        # Unexpected error during validation - fail closed for security
        error_msg = f"Unexpected error validating host {host}: {e}"
        logger.error(error_msg)
        return False, error_msg


def is_port_allowed(port: int, allowed_ports: Optional[set] = None) -> Tuple[bool, Optional[str]]:
    """
    Check if a port is in the allowed list for TLS connections.

    Args:
        port (int): The port number to check.
        allowed_ports (Optional[set]): Set of allowed port numbers.
                                       If None, all ports 1-65535 are allowed.

    Returns:
        Tuple[bool, Optional[str]]:
            - True if port is allowed, False otherwise
            - Error message if blocked, None otherwise

    Example:
        >>> is_port_allowed(443, {443, 8443})
        (True, None)
        >>> is_port_allowed(22, {443, 8443})
        (False, 'Port 22 is not in the allowed list: {443, 8443}')
    """
    # If no allowed_ports list is provided, allow all valid ports
    if allowed_ports is None:
        if 1 <= port <= 65535:
            return True, None
        else:
            return False, f"Port {port} is out of valid range (1-65535)"

    # Check against allowed ports list
    if port in allowed_ports:
        return True, None
    else:
        return False, f"Port {port} is not in the allowed list: {sorted(allowed_ports)}"


# Default User-Agent applied to safe_http_fetch when callers do not override it.
_DEFAULT_USER_AGENT = "Python-CertCheck/1.3"

# Schemes that safe_http_fetch is allowed to dispatch.
_ALLOWED_SCHEMES = frozenset({"http", "https"})


def _allow_internal_ips_from_env() -> bool:
    """
    Read the ``ALLOW_INTERNAL_IPS`` environment variable.

    Returns
    -------
    bool
        ``True`` when the environment variable is set to ``"true"``
        (case-insensitive), ``False`` otherwise. Defaults to ``False``
        so SSRF protection is the default posture.
    """
    return os.getenv("ALLOW_INTERNAL_IPS", "false").lower() == "true"


def safe_http_fetch(
    url: str,
    *,
    method: str = "GET",
    data: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 10.0,
    max_redirects: int = 5,
) -> Optional[requests.Response]:
    """
    Issue an HTTP(S) request with per-hop SSRF validation and manual redirect handling.

    The function performs the following checks before each network hop
    (initial URL plus every redirect target) to prevent SSRF attacks
    that abuse 3xx responses to pivot to internal addresses:

    * the URL must use the ``http`` or ``https`` scheme;
    * the host must pass :func:`validate_host_for_connection`, honoring
      the ``ALLOW_INTERNAL_IPS`` environment variable;
    * automatic redirect following provided by :mod:`requests` is
      disabled — redirects are followed manually up to ``max_redirects``
      hops, with the same validation re-applied for each ``Location``.

    Any failure (validation, transport error, non-2xx after redirects,
    too many redirects, malformed redirect target) results in ``None``,
    so call sites can keep treating fetch failures as soft errors —
    matching the previous behavior of the migrated callers.

    Parameters
    ----------
    url : str
        The absolute URL to fetch. Must use ``http`` or ``https``.
    method : str, optional
        HTTP method to use. Only ``"GET"`` and ``"POST"`` are expected
        by the current callers; other methods are passed through to
        :mod:`requests` unchanged. Defaults to ``"GET"``.
    data : bytes, optional
        Optional request body, forwarded as-is to :mod:`requests`.
    headers : dict[str, str], optional
        Optional HTTP headers. A default ``User-Agent`` is added when
        the caller does not provide one.
    timeout : float, optional
        Per-request timeout in seconds, applied to every hop.
        Defaults to ``10.0``.
    max_redirects : int, optional
        Maximum number of 3xx hops to follow. Defaults to ``5``.

    Returns
    -------
    requests.Response or None
        The successful response on the final hop, or ``None`` when any
        hop is rejected, errors out, or the chain exceeds
        ``max_redirects``.

    Examples
    --------
    >>> # Block direct connection to a private IP
    >>> safe_http_fetch("http://127.0.0.1/")  # doctest: +SKIP
    None

    >>> # Reject non-HTTP schemes outright
    >>> safe_http_fetch("file:///etc/passwd")  # doctest: +SKIP
    None
    """
    logger = logging.getLogger("certcheck")

    # Normalize headers and apply a default User-Agent so call sites
    # do not need to repeat it; preserve any caller-provided override.
    request_headers: Dict[str, str] = dict(headers or {})
    if not any(name.lower() == "user-agent" for name in request_headers):
        request_headers["User-Agent"] = _DEFAULT_USER_AGENT

    allow_private = _allow_internal_ips_from_env()
    method_upper = method.upper()
    current_url = url

    for hop in range(max_redirects + 1):
        parsed = urlparse(current_url)
        if parsed.scheme not in _ALLOWED_SCHEMES:
            logger.warning(
                "safe_http_fetch: refusing non-HTTP(S) URL '%s' (scheme=%r)",
                current_url,
                parsed.scheme,
            )
            return None

        host = parsed.hostname
        if not host:
            logger.warning("safe_http_fetch: URL '%s' has no hostname", current_url)
            return None

        # Determine the effective port for the validation step. Fall back
        # to the scheme default when the URL does not pin one explicitly.
        try:
            port = parsed.port if parsed.port is not None else (
                443 if parsed.scheme == "https" else 80
            )
        except ValueError:
            logger.warning("safe_http_fetch: URL '%s' has an invalid port", current_url)
            return None

        is_valid, validation_error = validate_host_for_connection(
            host, port, allow_private_ips=allow_private
        )
        if not is_valid:
            logger.warning(
                "safe_http_fetch: blocked %s '%s' - %s",
                "redirect to" if hop > 0 else "request to",
                current_url,
                validation_error,
            )
            return None

        try:
            response = requests.request(
                method_upper,
                current_url,
                data=data,
                headers=request_headers,
                timeout=timeout,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as exc:
            logger.warning(
                "safe_http_fetch: transport error fetching '%s': %s",
                current_url,
                exc,
            )
            return None

        # Follow 3xx redirects manually so we can re-validate each hop.
        if response.is_redirect or response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location")
            if not location:
                logger.warning(
                    "safe_http_fetch: %s response from '%s' had no Location header",
                    response.status_code,
                    current_url,
                )
                return None

            # Resolve relative redirects against the current URL.
            next_url = urljoin(current_url, location)
            logger.debug(
                "safe_http_fetch: redirect %s -> '%s' (hop %d)",
                response.status_code,
                next_url,
                hop + 1,
            )

            # RFC 7231: 303 forces GET; 301/302 historically behave the
            # same way for cross-method redirects in the wild. 307/308
            # preserve method and body. We err on the safe side and only
            # preserve method/body for 307/308.
            if response.status_code in (301, 302, 303):
                method_upper = "GET"
                data = None

            current_url = next_url
            continue

        if not response.ok:
            logger.warning(
                "safe_http_fetch: non-success status %d from '%s'",
                response.status_code,
                current_url,
            )
            return None

        return response

    logger.warning(
        "safe_http_fetch: exceeded max_redirects=%d starting from '%s'",
        max_redirects,
        url,
    )
    return None
