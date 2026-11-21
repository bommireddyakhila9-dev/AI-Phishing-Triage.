"""
URLhaus (abuse.ch) Threat Intelligence Integration Module
Queries URLhaus database for malware URLs, payload distribution indicators, and tags.
Includes graceful error handling and offline/demo fallback mode.
"""

import os
from typing import Any, Dict, Optional
from dotenv import load_dotenv
import requests

load_dotenv()

URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY", "")


def query_urlhaus(url: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Queries abuse.ch URLhaus API for malware URL records.
    """
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    headers = {"Accept": "application/json"}
    key = api_key or os.getenv("URLHAUS_API_KEY", URLHAUS_API_KEY)
    if key and key != "your_urlhaus_api_key_here":
        headers["Auth-Key"] = key

    try:
        data = {"url": url}
        response = requests.post(endpoint, data=data, headers=headers, timeout=6)
        if response.status_code == 200:
            result = response.json()
            status = result.get("query_status", "")

            if status == "ok":
                return {
                    "success": True,
                    "is_simulated": False,
                    "is_listed": True,
                    "threat": result.get("threat", "Malware Download"),
                    "tags": result.get("tags") or [],
                    "url_status": result.get("url_status", "unknown"),
                    "reporter": result.get("reporter", "Anonymous"),
                    "date_added": result.get("date_added", ""),
                    "lartis": result.get("lartis", ""),
                    "status_message": f"URL is actively listed on URLhaus (Threat: {result.get('threat')}).",
                }
            elif status == "no_results":
                return {
                    "success": True,
                    "is_simulated": False,
                    "is_listed": False,
                    "threat": "None",
                    "tags": [],
                    "url_status": "Clean / Not Listed",
                    "reporter": "N/A",
                    "date_added": "N/A",
                    "status_message": "URL not found in URLhaus malware database.",
                }
            else:
                return get_simulated_urlhaus_result(url, reason=f"URLhaus status: {status}")

    except Exception as exc:
        return get_simulated_urlhaus_result(url, reason=f"Network/API failure: {str(exc)}")

    return get_simulated_urlhaus_result(url, reason="No response from URLhaus.")


def get_simulated_urlhaus_result(url: str, reason: str = "") -> Dict[str, Any]:
    """
    Generates realistic fallback threat intelligence for demonstration when URLhaus is offline or unconfigured.
    """
    lower = url.lower()
    is_malware = any(term in lower for term in [
        "payload", "dropper", "beacon", "trojan", "xmrig", "c2", "exe", "bin", "msi", "ps1"
    ])

    if is_malware:
        return {
            "success": True,
            "is_simulated": True,
            "simulation_notice": f"Demo URLhaus Intel ({reason})",
            "is_listed": True,
            "threat": "malware_download",
            "tags": ["executable", "stealer", "trojan-dropper"],
            "url_status": "online",
            "reporter": "threat_hunter_soc",
            "date_added": "2026-11-20 14:22:01 UTC",
            "status_message": "URL confirmed in simulated URLhaus database (Threat: malware_download).",
        }

    return {
        "success": True,
        "is_simulated": True,
        "simulation_notice": f"Demo URLhaus Intel ({reason})",
        "is_listed": False,
        "threat": "None",
        "tags": [],
        "url_status": "Clean / Not Listed",
        "reporter": "N/A",
        "date_added": "N/A",
        "status_message": "URL not found in simulated URLhaus malware database.",
    }
