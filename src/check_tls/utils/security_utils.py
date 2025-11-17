"""
security_utils.py

Security validation utilities for preventing SSRF and other attacks.
Provides functions to validate domains and IP addresses before making connections.
"""

import ipaddress
import socket
import logging
from typing import Tuple, Optional


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
