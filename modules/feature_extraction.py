"""
URL Feature Extraction Module
Extracts 20 lexical, structural, and heuristic security features from URLs
for Machine Learning classification and SHAP explainability.
"""

import math
import re
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse
import pandas as pd


# List of popular brands frequently targeted by phishing campaigns
TARGET_BRANDS = [
    "paypal", "google", "apple", "microsoft", "netflix", "amazon",
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica",
    "citibank", "coinbase", "binance", "metamask", "whatsapp", "dropbox",
    "adobe", "ebay", "spotify", "steam", "dhl", "fedex", "usps"
]

# Legitimate apex domains for those brands to avoid false brand impersonation flags
LEGITIMATE_BRAND_DOMAINS = {
    "paypal": ["paypal.com", "paypal-communication.com"],
    "google": ["google.com", "google.co.uk", "google.ca", "google.com.au", "google.de", "google.fr", "youtube.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "azure.com", "msn.com", "bing.com"],
    "netflix": ["netflix.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "aws.amazon.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "citibank": ["citibank.com", "citi.com"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "metamask": ["metamask.io"],
    "whatsapp": ["whatsapp.com"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
    "ebay": ["ebay.com"],
    "spotify": ["spotify.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com"],
}

# Suspicious high-abuse TLDs commonly seen in phishing and spam
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "work", "icu",
    "cam", "rest", "country", "wang", "kim", "zip", "mov", "surf", "live",
    "loan", "click", "fit", "gdn", "racing", "monster", "date", "faith"
}

# Known URL shortening services
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly",
    "rebrand.ly", "cutt.ly", "snip.ly", "cli.re", "s.id", "shorturl.at", "rb.gy"
}

# Keywords frequently present in phishing lures
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "update", "banking", "secure",
    "account", "signin", "sign-in", "wallet", "confirm", "password",
    "webscr", "authenticate", "service", "security", "alert", "recover",
    "billing", "invoice", "ebayisapi", "wp-content", "admin", "client"
]

FEATURE_COLUMNS = [
    "url_length",
    "domain_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_digits",
    "num_special_chars",
    "num_subdomains",
    "is_ip_address",
    "has_https",
    "has_suspicious_keywords",
    "is_shortened",
    "has_at_symbol",
    "has_unusual_port",
    "has_encoded_chars",
    "excessive_redirect_signs",
    "suspicious_tld",
    "domain_entropy",
    "brand_impersonation",
    "suspicious_query_params",
]


def calculate_entropy(text: str) -> float:
    """
    Computes the Shannon entropy of a string (useful for detecting DGA or obfuscated domains).
    """
    if not text:
        return 0.0
    prob_dict = {}
    for char in text:
        prob_dict[char] = prob_dict.get(char, 0) + 1
    entropy = 0.0
    text_len = len(text)
    for count in prob_dict.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_features_dict(url: str) -> Dict[str, Any]:
    """
    Extracts 20 concrete security features from a single URL.
    Returns a dictionary of feature names mapped to numerical values.
    """
    if not url:
        return {col: 0 for col in FEATURE_COLUMNS}

    raw_url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url):
        raw_url = "http://" + raw_url

    parsed = urlparse(raw_url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    # 1. URL length
    url_length = len(raw_url)

    # 2. Domain length
    domain_length = len(hostname)

    # 3. Number of dots
    num_dots = raw_url.count(".")

    # 4. Number of hyphens
    num_hyphens = raw_url.count("-")

    # 5. Number of underscores
    num_underscores = raw_url.count("_")

    # 6. Number of digits
    num_digits = sum(c.isdigit() for c in raw_url)

    # 7. Number of special characters (excluding alphanumeric, '.', and '-')
    special_chars = set("!@#$%^&*()_+=[]{}|;:'\",<>?/~`\\")
    num_special_chars = sum(1 for c in raw_url if c in special_chars)

    # 8. Number of subdomains
    # e.g. login.secure.bank.com -> parts: ['login', 'secure', 'bank', 'com'] -> subdomains: 2
    host_parts = [p for p in hostname.split(".") if p]
    num_subdomains = max(0, len(host_parts) - 2) if len(host_parts) > 2 else 0

    # 9. Presence of IP address instead of domain
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    ipv6_pattern = r"^[0-9a-fA-F:]+$"
    is_ip = 1 if (re.match(ipv4_pattern, hostname) or (":" in hostname and re.match(ipv6_pattern, hostname))) else 0

    # 10. HTTPS usage
    has_https = 1 if parsed.scheme.lower() == "https" else 0

    # 11. Presence of suspicious keywords
    combined_text = (hostname + " " + path + " " + query).lower()
    keyword_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in combined_text)
    has_suspicious_keywords = 1 if keyword_hits > 0 else 0

    # 12. Presence of URL shortening services
    is_shortened = 1 if any(hostname == shortener or hostname.endswith("." + shortener) for shortener in SHORTENER_DOMAINS) else 0

    # 13. Presence of @ symbol
    has_at_symbol = 1 if "@" in raw_url else 0

    # 14. Presence of unusual ports
    has_unusual_port = 0
    if parsed.port and parsed.port not in (80, 443):
        has_unusual_port = 1

    # 15. Presence of encoded characters
    has_encoded_chars = 1 if bool(re.search(r"%[0-9a-fA-F]{2}", raw_url)) else 0

    # 16. Excessive redirects / open redirect signs
    redirect_indicators = ["http://", "https://", "redirect=", "url=", "dest=", "target=", "link="]
    excessive_redirect_signs = 0
    # Check if a second protocol appears after the first one
    if raw_url.lower().count("http://") + raw_url.lower().count("https://") > 1:
        excessive_redirect_signs = 1
    elif any(ind in query.lower() for ind in ["redirect=", "url=", "dest=", "target="]):
        excessive_redirect_signs = 1

    # 17. Suspicious TLD
    tld = host_parts[-1] if host_parts else ""
    suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # 18. Domain entropy
    domain_entropy = calculate_entropy(hostname)

    # 19. Brand impersonation
    brand_impersonation = 0
    for brand, legit_domains in LEGITIMATE_BRAND_DOMAINS.items():
        if brand in combined_text:
            # Check if current hostname is actually the legitimate domain
            is_legit = any(hostname == legit or hostname.endswith("." + legit) for legit in legit_domains)
            if not is_legit:
                brand_impersonation = 1
                break

    # 20. Suspicious query parameters
    parsed_query = parse_qs(query)
    suspicious_params = {"token", "redirect_url", "callback", "session", "auth", "pass", "login_challenge", "account_id"}
    suspicious_query_params = 1 if any(param in parsed_query for param in suspicious_params) else 0

    return {
        "url_length": int(url_length),
        "domain_length": int(domain_length),
        "num_dots": int(num_dots),
        "num_hyphens": int(num_hyphens),
        "num_underscores": int(num_underscores),
        "num_digits": int(num_digits),
        "num_special_chars": int(num_special_chars),
        "num_subdomains": int(num_subdomains),
        "is_ip_address": int(is_ip),
        "has_https": int(has_https),
        "has_suspicious_keywords": int(has_suspicious_keywords),
        "is_shortened": int(is_shortened),
        "has_at_symbol": int(has_at_symbol),
        "has_unusual_port": int(has_unusual_port),
        "has_encoded_chars": int(has_encoded_chars),
        "excessive_redirect_signs": int(excessive_redirect_signs),
        "suspicious_tld": int(suspicious_tld),
        "domain_entropy": float(domain_entropy),
        "brand_impersonation": int(brand_impersonation),
        "suspicious_query_params": int(suspicious_query_params),
    }


def extract_features_df(url: str) -> pd.DataFrame:
    """
    Extracts features for a single URL and returns a single-row pandas DataFrame.
    """
    features = extract_features_dict(url)
    return pd.DataFrame([features], columns=FEATURE_COLUMNS)


def batch_extract_features(urls: List[str]) -> pd.DataFrame:
    """
    Extracts features for a list of URLs and returns a pandas DataFrame.
    """
    records = [extract_features_dict(u) for u in urls]
    return pd.DataFrame(records, columns=FEATURE_COLUMNS)
