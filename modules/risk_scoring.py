"""
Security Risk Scoring Engine (SOAR Lite)
Combines ML threat probability, heuristic indicators, threat intelligence findings,
and domain reputation into a normalized 0-100 composite risk score.
"""

import os
from typing import Any, Dict, Optional
from dotenv import load_dotenv
import plotly.graph_objects as go

load_dotenv()


def get_risk_category(score: int) -> Dict[str, str]:
    """
    Maps 0-100 risk score to standard SOAR severity tiers and colors.
    """
    if score <= 20:
        return {"category": "Low Risk", "badge_class": "badge-low", "color": "#10b981", "severity": "Low"}
    elif score <= 40:
        return {"category": "Moderate Risk", "badge_class": "badge-moderate", "color": "#f59e0b", "severity": "Moderate"}
    elif score <= 60:
        return {"category": "Suspicious", "badge_class": "badge-suspicious", "color": "#fb923c", "severity": "Suspicious"}
    elif score <= 80:
        return {"category": "High Risk", "badge_class": "badge-high", "color": "#f87171", "severity": "High"}
    else:
        return {"category": "Critical Risk", "badge_class": "badge-critical", "color": "#ef4444", "severity": "Critical"}


def compute_heuristic_score(features: Dict[str, Any]) -> int:
    """
    Computes a 0-100 score strictly from URL lexical and structural heuristics.
    """
    raw_score = 0

    if features.get("brand_impersonation", 0):
        raw_score += 30
    if features.get("is_ip_address", 0):
        raw_score += 25
    if features.get("suspicious_tld", 0):
        raw_score += 20
    if features.get("has_suspicious_keywords", 0):
        raw_score += 20
    if not features.get("has_https", 0):
        raw_score += 15
    if features.get("is_shortened", 0):
        raw_score += 15
    if features.get("excessive_redirect_signs", 0):
        raw_score += 15
    if features.get("has_at_symbol", 0):
        raw_score += 20
    if features.get("has_unusual_port", 0):
        raw_score += 15
    if features.get("domain_entropy", 0.0) > 3.8:
        raw_score += 15
    if features.get("num_subdomains", 0) >= 3:
        raw_score += 10
    if features.get("has_encoded_chars", 0):
        raw_score += 10

    return min(100, raw_score)


def compute_threat_intel_score(vt_result: Dict[str, Any], urlhaus_result: Dict[str, Any]) -> int:
    """
    Calculates threat score based on vendor detections from VirusTotal and URLhaus.
    """
    score = 0
    vt_malicious = vt_result.get("malicious_count", 0)
    vt_suspicious = vt_result.get("suspicious_count", 0)

    # URLhaus listing is an immediate high-confidence malware indicator
    if urlhaus_result.get("is_listed", False):
        score = max(score, 90)

    # VirusTotal engine detections
    if vt_malicious >= 5:
        score = max(score, 100)
    elif vt_malicious >= 3:
        score = max(score, 80)
    elif vt_malicious >= 1:
        score = max(score, 55)
    elif vt_suspicious >= 2:
        score = max(score, 40)
    elif vt_suspicious == 1:
        score = max(score, 25)

    return min(100, score)


def compute_domain_reputation_score(domain_intel: Dict[str, Any]) -> int:
    """
    Calculates threat score based on domain age and registration characteristics.
    """
    age_days = domain_intel.get("age_days", 365)
    if domain_intel.get("is_newly_registered", False) or (0 <= age_days < 30):
        return 75
    elif age_days < 90:
        return 45
    elif age_days < 365:
        return 20
    else:
        # Well-established domain (> 1 year old)
        return 5


def calculate_composite_risk_score(
    ml_result: Dict[str, Any],
    features: Dict[str, Any],
    vt_result: Dict[str, Any],
    urlhaus_result: Dict[str, Any],
    domain_intel: Dict[str, Any],
    custom_weights: Optional[Dict[str, float]] = None
) -> Dict[str, Any]:
    """
    Combines all detection components into a final normalized 0-100 risk score.
    """
    weights = custom_weights or {
        "ml": float(os.getenv("WEIGHT_ML_MODEL", 0.40)),
        "heuristics": float(os.getenv("WEIGHT_HEURISTICS", 0.25)),
        "threat_intel": float(os.getenv("WEIGHT_THREAT_INTEL", 0.25)),
        "domain": float(os.getenv("WEIGHT_DOMAIN_REPUTATION", 0.10)),
    }

    # Normalize weights if sum != 1.0
    total_w = sum(weights.values()) or 1.0
    w_ml = weights["ml"] / total_w
    w_heu = weights["heuristics"] / total_w
    w_ti = weights["threat_intel"] / total_w
    w_dom = weights["domain"] / total_w

    # Sub-scores (0-100)
    threat_prob = ml_result.get("threat_probability", 0.0)
    ml_score = int(round(threat_prob * 100))
    heuristic_score = compute_heuristic_score(features)
    threat_intel_score = compute_threat_intel_score(vt_result, urlhaus_result)
    domain_score = compute_domain_reputation_score(domain_intel)

    # Composite weighted score
    composite = (
        (w_ml * ml_score) +
        (w_heu * heuristic_score) +
        (w_ti * threat_intel_score) +
        (w_dom * domain_score)
    )

    final_score = int(round(max(0, min(100, composite))))
    category_info = get_risk_category(final_score)

    disclaimer = (
        "Note: Risk score is an automated statistical and heuristic assessment. "
        "It should be correlated with organizational threat landscape and context."
    )

    return {
        "risk_score": final_score,
        "risk_category": category_info["category"],
        "severity": category_info["severity"],
        "color": category_info["color"],
        "badge_class": category_info["badge_class"],
        "components": {
            "ml_score": ml_score,
            "heuristic_score": heuristic_score,
            "threat_intel_score": threat_intel_score,
            "domain_score": domain_score,
        },
        "weights": {
            "ml": w_ml,
            "heuristics": w_heu,
            "threat_intel": w_ti,
            "domain": w_dom,
        },
        "disclaimer": disclaimer,
    }


def create_risk_gauge_chart(score: int, category: str, color: str) -> go.Figure:
    """
    Renders an interactive Plotly radial gauge chart showing risk level.
    """
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            domain={"x": [0, 1], "y": [0, 1]},
            title={"text": f"<b>{category}</b>", "font": {"size": 18, "color": color}},
            number={"suffix": "/100", "font": {"size": 32, "color": "#f8fafc"}},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#94a3b8", "tickfont": {"color": "#94a3b8"}},
                "bar": {"color": color, "thickness": 0.28},
                "bgcolor": "#1e293b",
                "borderwidth": 1,
                "bordercolor": "#334155",
                "steps": [
                    {"range": [0, 20], "color": "rgba(16, 185, 129, 0.25)"},
                    {"range": [20, 40], "color": "rgba(245, 158, 11, 0.25)"},
                    {"range": [40, 60], "color": "rgba(249, 115, 22, 0.25)"},
                    {"range": [60, 80], "color": "rgba(239, 68, 68, 0.25)"},
                    {"range": [80, 100], "color": "rgba(220, 38, 38, 0.45)"},
                ],
                "threshold": {
                    "line": {"color": "#ffffff", "width": 3},
                    "thickness": 0.8,
                    "value": score,
                },
            },
        )
    )

    fig.update_layout(
        paper_bgcolor="#0f172a",
        font={"color": "#f8fafc"},
        margin=dict(l=25, r=25, t=40, b=20),
        height=260,
    )
    return fig
