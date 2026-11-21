"""
Tests for ML model loading, predictions, and batch processing.
"""

import pytest
from modules.ml_model import batch_predict, get_model, predict_url


def test_model_loading():
    model, features = get_model()
    assert model is not None
    assert len(features) == 20


def test_predict_single_url():
    url = "https://www.google.com"
    res = predict_url(url)

    assert "prediction" in res
    assert "confidence" in res
    assert "threat_probability" in res
    assert res["prediction"] in ["Benign", "Phishing", "Malicious", "Suspicious"]
    assert 0.0 <= res["confidence"] <= 1.0


def test_batch_prediction():
    urls = [
        "https://www.google.com",
        "http://paypal-security-verification-login.com.account-update.xyz/signin",
    ]
    batch_res = batch_predict(urls)
    assert len(batch_res) == 2
    for r in batch_res:
        assert "prediction" in r
        assert "confidence" in r
