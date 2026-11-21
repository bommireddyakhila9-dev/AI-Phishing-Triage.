"""
URL Validation and Sanitization Module
Implements robust validation, SSRF protection, defanging/refanging, and scheme normalization.
"""

import ipaddress
import re
from typing import Tuple
from urllib.parse import urlparse


# Private/Reserved IPv4/IPv6 networks to reject for SSRF mitigation
RESERVED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "local",
    "metadata.google.internal",
    "instance-data",
}


def refang_url(url: str) -> str:
    """
    Converts a defanged URL back into a standard URL.
    E.g., 'hxxps[://]example[.]com' -> 'https://example.com'
    """
    if not url:
        return ""
    text = url.strip()
    text = re.sub(r"^hxxps?", lambda m: "https" if "s" in m.group(0).lower() else "http", text, flags=re.IGNORECASE)
    text = text.replace("[://]", "://").replace("(://)", "://")
    text = text.replace("[.]", ".").replace("(.)", ".")
    text = text.replace("[:]", ":").replace("(:)", ":")
    text = text.replace("[/]", "/").replace("(/)", "/")
    return text


def defang_url(url: str) -> str:
    """
    Defangs a URL for safe UI display so that it cannot be accidentally clicked or linked.
    E.g., 'https://evil.com/login' -> 'hxxps://evil[.]com/login'
    """
    if not url:
        return ""
    cleaned = url.strip()
    # Replace scheme
    cleaned = re.sub(r"^https://", "hxxps://", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^http://", "hxxp://", cleaned, flags=re.IGNORECASE)
    # Defang dots in the host portion
    parsed = urlparse(cleaned if "://" in cleaned else "hxxp://" + cleaned)
    host = parsed.netloc
    if host:
        defanged_host = host.replace(".", "[.]")
        # reconstruct
        return cleaned.replace(host, defanged_host, 1)
    return cleaned.replace(".", "[.]")


def normalize_url(url: str) -> str:
    """
    Normalizes URL string: strips whitespace, lowercases scheme/host, defaults missing scheme to http://
    """
    if not url:
        return ""
    u = refang_url(url.strip())
    # Strip wrapping quotes
    if (u.startswith('"') and u.endswith('"')) or (u.startswith("'") and u.endswith("'")):
        u = u[1:-1].strip()

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
        u = "http://" + u
    return u


def is_valid_url(url: str) -> Tuple[bool, str]:
    """
    Validates general URL structure and returns (is_valid, reason_or_normalized_url).
    """
    if not url or not isinstance(url, str):
        return False, "URL cannot be empty."

    raw = url.strip()
    if len(raw) > 2048:
        return False, "URL exceeds maximum permitted length (2048 characters)."

    norm = normalize_url(raw)
    try:
        parsed = urlparse(norm)
    except Exception as exc:
        return False, f"Failed to parse URL: {str(exc)}"

    if parsed.scheme.lower() not in {"http", "https"}:
        return False, f"Unsupported scheme '{parsed.scheme}'. Only HTTP and HTTPS are supported."

    hostname = parsed.hostname
    if not hostname:
        return False, "Missing valid domain name or IP address."

    # Validate hostname characters
    if not re.match(r"^[a-zA-Z0-9.-]+$", hostname):
        return False, f"Invalid characters detected in domain: {hostname}"

    if len(hostname) > 253:
        return False, "Hostname length exceeds maximum RFC limit (253 characters)."

    return True, norm


def is_safe_for_network(url: str) -> Tuple[bool, str]:
    """
    Enforces SSRF prevention and checks if the URL is safe for external queries/reputation checks.
    Blocks private IP ranges, loopbacks, internal hostnames, and AWS/GCP metadata endpoints.
    """
    valid, res = is_valid_url(url)
    if not valid:
        return False, res

    parsed = urlparse(res)
    hostname = (parsed.hostname or "").lower()

    if hostname in BLOCKED_HOSTNAMES:
        return False, f"SSRF Protection: Hostname '{hostname}' is reserved/internal."

    if hostname.endswith(".internal") or hostname.endswith(".local"):
        return False, f"SSRF Protection: Domain '{hostname}' belongs to an internal namespace."

    # Check if host is direct IP
    try:
        ip_obj = ipaddress.ip_address(hostname)
        for net in RESERVED_NETWORKS:
            if ip_obj in net:
                return False, f"SSRF Protection: IP address '{hostname}' belongs to reserved network {net}."
    except ValueError:
        # Not a raw IP literal, which is standard for domain names
        pass

    # Port restriction: only standard web ports allowed
    if parsed.port:
        if parsed.port not in {80, 443, 8080, 8443}:
            return False, f"Port {parsed.port} is non-standard and rejected by security policy."

    return True, "URL is valid and passes SSRF security verification."
