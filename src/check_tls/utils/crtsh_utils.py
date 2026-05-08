"""
crtsh_utils.py

Utility functions for querying crt.sh for certificate transparency logs.
Provides helpers to fetch certificate data for a domain and its parent domains.
"""

import os
import urllib.request
import urllib.error
import json
import socket
import logging
from importlib.metadata import PackageNotFoundError, version
from urllib.parse import quote_plus
from typing import Optional, List, Dict, Any

# Timeout in seconds for crt.sh HTTP requests
CRTSH_TIMEOUT = 15

# User-Agent header sent with every crt.sh request. Reflects the installed
# package version so server logs can correlate traffic to specific releases.
try:
    _pkg_version: str = version("check-tls")
except PackageNotFoundError:  # pragma: no cover
    _pkg_version = "unknown"

USER_AGENT = f"check-tls/{_pkg_version}"

# Delay between successive crt.sh requests in query_crtsh_multi.
# Deliberate rate-limit to avoid hammering crt.sh. Override via the
# CHECK_TLS_CRTSH_DELAY environment variable (seconds, float).
try:
    CRTSH_RATE_LIMIT_DELAY_SEC = max(0.0, float(os.getenv("CHECK_TLS_CRTSH_DELAY", "0.5")))
except (TypeError, ValueError):
    CRTSH_RATE_LIMIT_DELAY_SEC = 0.5


def get_parent_domains(domain: str) -> list:
    """
    Generate all parent domains for a given domain.

    Args:
        domain (str): The domain to process (e.g., 'a.b.c.com').

    Returns:
        list: List of parent domains, from most specific to least (e.g., ['a.b.c.com', 'b.c.com', 'c.com']).

    Example:
        >>> get_parent_domains('a.b.c.com')
        ['a.b.c.com', 'b.c.com', 'c.com']
    """
    parts = domain.split('.')
    # Only keep domains with at least two parts (to avoid TLDs)
    return ['.'.join(parts[i:]) for i in range(len(parts)-1) if len(parts[i:]) >= 2]


def query_crtsh(domain: str) -> Optional[List[Dict[str, Any]]]:
    """
    Query crt.sh for certificates related to the given domain.

    Args:
        domain (str): The domain to search for.

    Returns:
        Optional[List[Dict[str, Any]]]: List of certificate entries (as dicts), or None if the query fails.

    Example:
        >>> certs = query_crtsh('example.com')
        >>> if certs:
        ...     print(f"Found {len(certs)} certificates for example.com")
    """
    url = f"https://crt.sh/?q={quote_plus(domain)}&output=json"
    logging.info(f"Querying crt.sh for {domain}")
    try:
        req = urllib.request.Request(
            url, headers={'User-Agent': USER_AGENT}
        )
        with urllib.request.urlopen(req, timeout=CRTSH_TIMEOUT) as response:
            if response.status == 200:
                data = json.loads(response.read())
                # Defensive: not all entries may have min_cert_id (API bug or format change)
                # Accept either min_cert_id or id for deduplication and counting
                unique_certs = {}
                for entry in data:
                    cert_id = entry.get('min_cert_id') or entry.get('id')
                    if cert_id is not None:
                        unique_certs[cert_id] = entry
                        if 'min_cert_id' not in entry:
                            logging.info(f"crt.sh entry missing min_cert_id for {domain}: {entry}")
                    else:
                        logging.warning(f"crt.sh entry missing both min_cert_id and id for {domain}: {entry}")
                return list(unique_certs.values())
            else:
                logging.warning(f"crt.sh query for {domain} returned status {response.status}")
                return None
    except urllib.error.URLError as e:
        logging.warning(f"Could not connect to crt.sh for {domain}: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.warning(f"Failed to parse crt.sh JSON response for {domain}: {e}")
        return None
    except socket.timeout:
        logging.warning(f"Connection to crt.sh timed out for domain {domain}")
        return None
    except Exception as e:
        logging.warning(f"An unexpected error occurred during crt.sh query for {domain}: {e}")
        return None


def query_crtsh_multi(domain: str) -> dict:
    """
    Query crt.sh for the domain and all its parent domains.

    Args:
        domain (str): The domain to search for.

    Returns:
        dict: Dictionary mapping each parent domain to its list of certificate entries (or None if failed).

    Example:
        >>> results = query_crtsh_multi('a.b.c.com')
        >>> for d, certs in results.items():
        ...     print(f"{d}: {len(certs) if certs else 0} certs")
    """
    from time import sleep

    results = {}
    for d in get_parent_domains(domain):
        res = query_crtsh(d)
        results[d] = res
        sleep(CRTSH_RATE_LIMIT_DELAY_SEC)
    return results
