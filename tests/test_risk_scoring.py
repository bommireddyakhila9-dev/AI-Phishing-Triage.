"""
Tests for composite risk scoring and category assignment.
"""

import pytest
from modules.risk_scoring import calculate_composite_risk_score, compute_heuristic_score, get_risk_category


def test_get_risk_category_bounds():
    assert get_risk_category(0)["category"] == "Low Risk"
    assert get_risk_category(20)["category"] == "Low Risk"
    assert get_risk_category(25)["category"] == "Moderate Risk"
    assert get_risk_category(50)["category"] == "Suspicious"
    assert get_risk_category(75)["category"] == "High Risk"
    assert get_risk_category(95)["category"] == "Critical Risk"


def test_heuristic_scoring():
    benign_feat = {
        "brand_impersonation": 0,
        "is_ip_address": 0,
        "suspicious_tld": 0,
        "has_suspicious_keywords": 0,
        "has_https": 1,
        "is_shortened": 0,
        "excessive_redirect_signs": 0,
        "has_at_symbol": 0,
        "has_unusual_port": 0,
        "domain_entropy": 2.1,
        "num_subdomains": 0,
        "has_encoded_chars": 0,
    }
    benign_score = compute_heuristic_score(benign_feat)
    assert benign_score == 0

    malicious_feat = {
        "brand_impersonation": 1,
        "is_ip_address": 1,
        "suspicious_tld": 1,
        "has_suspicious_keywords": 1,
        "has_https": 0,
        "is_shortened": 1,
        "excessive_redirect_signs": 1,
        "has_at_symbol": 1,
        "has_unusual_port": 1,
        "domain_entropy": 4.5,
        "num_subdomains": 4,
        "has_encoded_chars": 1,
    }
    mal_score = compute_heuristic_score(malicious_feat)
    assert mal_score == 100  # Capped at 100


def test_composite_risk_calculation():
    ml_res = {"threat_probability": 0.90}
    features = {"brand_impersonation": 1, "is_ip_address": 0, "has_https": 0, "suspicious_tld": 1}
    vt_res = {"malicious_count": 5}
    urlhaus_res = {"is_listed": True}
    domain_intel = {"is_newly_registered": True, "age_days": 10}

    res = calculate_composite_risk_score(ml_res, features, vt_res, urlhaus_res, domain_intel)
    assert 0 <= res["risk_score"] <= 100
    assert res["risk_score"] >= 70
    assert res["severity"] in ("High", "Critical")
