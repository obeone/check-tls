# crt.sh querying logic

import urllib.request
import json
import socket
import logging
from urllib.parse import quote_plus
from typing import Optional, List, Dict, Any

CRTSH_TIMEOUT = 15

def get_parent_domains(domain: str) -> list:
    """Generate parent domains for a given domain (e.g., a.b.c.com -> ['a.b.c.com', 'b.c.com', 'c.com'])"""
    parts = domain.split('.')
    return ['.'.join(parts[i:]) for i in range(len(parts)-1) if len(parts[i:]) >= 2]

def query_crtsh(domain: str) -> Optional[List[Dict[str, Any]]]:
    """Queries crt.sh for certificates related to the domain."""
    url = f"https://crt.sh/?q={quote_plus(domain)}&output=json"
    logging.info(f"Querying crt.sh for {domain}")
    try:
        req = urllib.request.Request(
            url, headers={'User-Agent': 'Python-CertCheck/1.3'})
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
    """Query crt.sh for the domain and all parent domains."""
    from time import sleep
    results = {}
    for d in get_parent_domains(domain):
        res = query_crtsh(d)
        results[d] = res
        sleep(0.5)  # avoid hammering crt.sh
    return results
