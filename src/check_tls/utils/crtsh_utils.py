# crt.sh querying logic

import urllib.request
import json
import socket
import logging
from urllib.parse import quote_plus
from typing import Optional, List, Dict, Any

CRTSH_TIMEOUT = 15

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
                unique_certs = {entry['min_cert_id']: entry for entry in data}
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
