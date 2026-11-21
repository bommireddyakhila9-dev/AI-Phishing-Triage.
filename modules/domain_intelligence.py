"""
Domain Intelligence Module
Retrieves domain registration metadata, registrar details, domain age,
and DNS resolution records using public RDAP and standard DNS lookups.
"""

from datetime import datetime
import os
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import requests


def get_dns_records(domain: str) -> List[str]:
    """
    Safely resolves IPv4 addresses for the given domain using socket with a strict timeout.
    """
    if not domain:
        return []
    try:
        socket.setdefaulttimeout(3.0)
        addr_info = socket.getaddrinfo(domain, None, socket.AF_INET)
        ips = sorted(list({entry[4][0] for entry in addr_info}))
        return ips
    except Exception:
        return []


def query_domain_intelligence(url: str) -> Dict[str, Any]:
    """
    Fetches domain age, registrar, registration dates, and DNS records.
    """
    parsed = urlparse(url if "://" in url else "http://" + url)
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        return {
            "domain": "Unknown",
            "registrar": "Unknown",
            "creation_date": "N/A",
            "expiration_date": "N/A",
            "age_days": 0,
            "dns_records": [],
            "is_newly_registered": False,
            "is_simulated": True,
        }

    # If hostname is an IP address
    if any(c.isdigit() for c in hostname) and all(c.isdigit() or c in ".:" for c in hostname):
        return {
            "domain": hostname,
            "registrar": "N/A (Raw IP Host)",
            "creation_date": "N/A",
            "expiration_date": "N/A",
            "age_days": 0,
            "dns_records": [hostname],
            "is_newly_registered": True,
            "is_simulated": False,
        }

    dns_ips = get_dns_records(hostname)

    # RDAP lookup for registration dates
    rdap_url = f"https://rdap.org/domain/{hostname}"
    try:
        resp = requests.get(rdap_url, timeout=5, headers={"Accept": "application/json"})
        if resp.status_code == 200:
            rdap_data = resp.json()
            events = rdap_data.get("events", [])
            entities = rdap_data.get("entities", [])

            creation_date_str = "Unknown"
            expiration_date_str = "Unknown"
            age_days = 365  # default

            for ev in events:
                action = ev.get("eventAction", "")
                date_val = ev.get("eventDate", "")
                if action == "registration":
                    creation_date_str = date_val[:10]
                    try:
                        dt = datetime.strptime(creation_date_str, "%Y-%m-%d")
                        age_days = max(0, (datetime.utcnow() - dt).days)
                    except Exception:
                        pass
                elif action == "expiration":
                    expiration_date_str = date_val[:10]

            registrar = "Unknown"
            for ent in entities:
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == "fn":
                                registrar = item[3]
                                break

            return {
                "domain": hostname,
                "registrar": registrar,
                "creation_date": creation_date_str,
                "expiration_date": expiration_date_str,
                "age_days": age_days,
                "dns_records": dns_ips,
                "is_newly_registered": age_days < 60,
                "is_simulated": False,
            }
    except Exception:
        pass

    # Fallback heuristic / demo domain intelligence
    return get_simulated_domain_intel(hostname, dns_ips)


def get_simulated_domain_intel(domain: str, dns_ips: List[str]) -> Dict[str, Any]:
    """
    Deterministic domain intelligence fallback when external RDAP is unreachable.
    """
    is_major = any(top in domain for top in ["google", "microsoft", "apple", "amazon", "github", "wikipedia"])

    if is_major:
        creation = "1997-09-15"
        expiration = "2028-09-13"
        registrar = "MarkMonitor, Inc."
        age_days = 10000
        newly_reg = False
    elif any(tld in domain for tld in [".xyz", ".top", ".icu", ".buzz", ".cam", ".click"]):
        creation = "2026-11-12"
        expiration = "2026-11-12"
        registrar = "NameSilo LLC / FastDomain"
        age_days = 9
        newly_reg = True
    else:
        creation = "2023-04-10"
        expiration = "2026-04-10"
        registrar = "GoDaddy.com, LLC"
        age_days = 1200
        newly_reg = False

    return {
        "domain": domain,
        "registrar": registrar,
        "creation_date": creation,
        "expiration_date": expiration,
        "age_days": age_days,
        "dns_records": dns_ips if dns_ips else ["104.21.55.2", "172.67.180.9"],
        "is_newly_registered": newly_reg,
        "is_simulated": True,
    }
