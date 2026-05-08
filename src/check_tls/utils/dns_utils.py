"""DNS utilities including CAA record checks."""

import os
from typing import Dict, Any

import dns.resolver
import dns.exception

try:
    DNS_TIMEOUT_SEC: float = max(0.1, float(os.getenv("CHECK_TLS_DNS_TIMEOUT", "2.0")))
except (TypeError, ValueError):
    DNS_TIMEOUT_SEC = 2.0

try:
    DNS_LIFETIME_SEC: float = max(0.1, float(os.getenv("CHECK_TLS_DNS_LIFETIME", "5.0")))
except (TypeError, ValueError):
    DNS_LIFETIME_SEC = 5.0


def query_caa(domain: str) -> Dict[str, Any]:
    """Query DNS CAA records for a domain.

    Uses a custom resolver with explicit per-attempt timeout and total lifetime
    cap so unresponsive resolvers fail fast instead of hanging indefinitely.

    Parameters
    ----------
    domain : str
        Domain to query.

    Returns
    -------
    Dict[str, Any]
        Summary with keys:

        - checked (bool): Whether the query was executed.
        - found (bool): Whether CAA records were found.
        - records (List[dict]): Parsed CAA records, each with keys
          ``flags`` (int), ``tag`` (str), ``value`` (str).
        - error (str | None): Error message if any.
    """
    result: Dict[str, Any] = {
        "checked": True,
        "found": False,
        "records": [],
        "error": None,
    }
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT_SEC
        resolver.lifetime = DNS_LIFETIME_SEC
        answers = resolver.resolve(domain, "CAA")
        for rdata in answers:
            result["records"].append({
                "flags": int(getattr(rdata, "flags", 0)),
                "tag": str(getattr(rdata, "tag", "")),
                "value": str(getattr(rdata, "value", "")),
            })
        result["found"] = len(result["records"]) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        # No CAA records exist for the domain. This is not an error.
        result["found"] = False
        result["records"] = []
    except dns.exception.Timeout as exc:
        result["error"] = (
            f"DNS query timed out after {DNS_LIFETIME_SEC}s lifetime "
            f"({DNS_TIMEOUT_SEC}s per attempt): {exc}"
        )
    except dns.exception.DNSException as exc:
        result["error"] = str(exc)
    return result
