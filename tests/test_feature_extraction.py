"""
Tests for URL feature extraction and entropy calculation.
"""

import pytest
from modules.feature_extraction import FEATURE_COLUMNS, calculate_entropy, extract_features_dict


def test_feature_columns_completeness():
    assert len(FEATURE_COLUMNS) == 20
    test_url = "http://paypal-security-update.xyz/login.php?user=1"
    features = extract_features_dict(test_url)

    assert len(features) == 20
    for col in FEATURE_COLUMNS:
        assert col in features, f"Missing feature: {col}"


def test_ip_address_detection():
    ip_url = "http://192.168.1.50:8080/payload.bin"
    features = extract_features_dict(ip_url)
    assert features["is_ip_address"] == 1
    assert features["has_unusual_port"] == 1

    domain_url = "https://www.google.com"
    features2 = extract_features_dict(domain_url)
    assert features2["is_ip_address"] == 0
    assert features2["has_unusual_port"] == 0


def test_brand_impersonation_detection():
    # Deceptive domain mimicking paypal
    phish_url = "http://paypal-login-account-verification.xyz/signin"
    features = extract_features_dict(phish_url)
    assert features["brand_impersonation"] == 1
    assert features["has_suspicious_keywords"] == 1
    assert features["suspicious_tld"] == 1

    # Legitimate apex domain
    legit_url = "https://www.paypal.com/signin"
    legit_features = extract_features_dict(legit_url)
    assert legit_features["brand_impersonation"] == 0


def test_shannon_entropy():
    # Low entropy (repetitive)
    low_ent = calculate_entropy("aaaaaaa")
    assert low_ent == 0.0

    # High entropy (random alphanumeric)
    high_ent = calculate_entropy("x82k194jd92qw9z")
    assert high_ent > 3.0
