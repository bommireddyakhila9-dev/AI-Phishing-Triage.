"""
VirusTotal Threat Intelligence Integration Module
Interacts with the VirusTotal v3 API for URL reputation and security vendor findings.
Provides full error handling, rate-limit resilience, and realistic demonstration fallbacks.
"""

import base64
import os
from typing import Any, Dict, Optional
from dotenv import load_dotenv
import requests

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")


def get_vt_url_id(url: str) -> str:
    """
    Computes base64 URL identifier without padding for VirusTotal v3 API.
    """
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def query_virustotal(url: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Queries VirusTotal v3 URL analysis endpoint.
    If no API key is provided or the endpoint fails, returns structured simulated threat intel.
    """
    key = api_key or os.getenv("VIRUSTOTAL_API_KEY", VIRUSTOTAL_API_KEY)

    if not key or key == "your_virustotal_api_key_here":
        return get_simulated_virustotal_result(url, reason="No VIRUSTOTAL_API_KEY configured in environment.")

    url_id = get_vt_url_id(url)
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "x-apikey": key,
        "Accept": "application/json",
    }

    try:
        response = requests.get(endpoint, headers=headers, timeout=8)
        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            vendor_results = attributes.get("last_analysis_results", {})

            # Filter top detecting vendors
            flagging_vendors = []
            for vendor, res in vendor_results.items():
                cat = res.get("category", "")
                if cat in ("malicious", "suspicious"):
                    flagging_vendors.append({
                        "engine": vendor,
                        "category": cat,
                        "result": res.get("result", "flagged"),
                    })

            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)
            harmless_count = stats.get("harmless", 0)
            undetected_count = stats.get("undetected", 0)
            total_engines = malicious_count + suspicious_count + harmless_count + undetected_count

            return {
                "success": True,
                "is_simulated": False,
                "url": url,
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
                "harmless_count": harmless_count,
                "undetected_count": undetected_count,
                "total_engines": total_engines,
                "reputation": attributes.get("reputation", 0),
                "flagging_vendors": flagging_vendors[:12],
                "last_scan_date": attributes.get("last_analysis_date", "Recently"),
                "status_message": f"{malicious_count} security vendors flagged this URL as malicious.",
            }
        elif response.status_code == 404:
            return {
                "success": True,
                "is_simulated": False,
                "url": url,
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "undetected_count": 0,
                "total_engines": 0,
                "reputation": 0,
                "flagging_vendors": [],
                "status_message": "URL not previously scanned in VirusTotal dataset.",
            }
        elif response.status_code == 429:
            return get_simulated_virustotal_result(url, reason="VirusTotal API rate limit reached (HTTP 429).")
        else:
            return get_simulated_virustotal_result(url, reason=f"VirusTotal API returned status {response.status_code}.")

    except Exception as exc:
        return get_simulated_virustotal_result(url, reason=f"Connection error: {str(exc)}")


def get_simulated_virustotal_result(url: str, reason: str = "") -> Dict[str, Any]:
    """
    Produces deterministic, realistic threat intelligence for offline/demo scenarios.
    """
    lower = url.lower()
    is_threat = any(term in lower for term in [
        "login", "verify", "account", "banking", "wallet", "pay", ".xyz", ".top", ".icu",
        "dropper", "beacon", "exploit", "trojan", "xmrig", "exe", "bin", "192.168"
    ])
    is_safe = any(domain in lower for domain in [
        "google.com", "microsoft.com", "apple.com", "amazon.com", "github.com", "wikipedia.org", "python.org"
    ])

    if is_safe:
        malicious = 0
        suspicious = 0
        harmless = 78
        undetected = 12
        vendors = []
    elif is_threat:
        malicious = 14
        suspicious = 5
        harmless = 45
        undetected = 26
        vendors = [
            {"engine": "Fortinet", "category": "malicious", "result": "phishing"},
            {"engine": "Kaspersky", "category": "malicious", "result": "trojan-url"},
            {"engine": "Sophos", "category": "malicious", "result": "malicious site"},
            {"engine": "BitDefender", "category": "malicious", "result": "phishing link"},
            {"engine": "Google Safebrowsing", "category": "malicious", "result": "social engineering"},
            {"engine": "ESET", "category": "suspicious", "result": "suspicious domain"},
        ]
    else:
        malicious = 2
        suspicious = 1
        harmless = 62
        undetected = 25
        vendors = [
            {"engine": "CRDF", "category": "suspicious", "result": "unrated threat"},
        ]

    total = malicious + suspicious + harmless + undetected
    return {
        "success": True,
        "is_simulated": True,
        "simulation_notice": f"Demo Threat Intelligence ({reason})",
        "url": url,
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "harmless_count": harmless,
        "undetected_count": undetected,
        "total_engines": total,
        "reputation": -35 if is_threat else (100 if is_safe else 10),
        "flagging_vendors": vendors,
        "status_message": f"{malicious} / {total} security vendors flagged this URL as malicious." if is_threat else "Clean reputation across major threat feeds.",
    }
