"""
Machine Learning Model Prediction Module
Handles loading the trained classifier, computing class probabilities,
and returning structured prediction outputs for single URLs and batches.
"""

import json
import os
from typing import Any, Dict, List, Optional
import joblib
import numpy as np
import pandas as pd

from modules.feature_extraction import (
    FEATURE_COLUMNS,
    batch_extract_features,
    extract_features_df,
    extract_features_dict,
)

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "model")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
COLUMNS_PATH = os.path.join(MODEL_DIR, "feature_columns.json")
METRICS_PATH = os.path.join(MODEL_DIR, "training_metrics.json")

_MODEL = None
_FEATURE_COLS = None


def get_model():
    """
    Lazy loads the trained classifier.
    """
    global _MODEL, _FEATURE_COLS
    if _MODEL is None:
        if not os.path.exists(MODEL_PATH):
            from model.train_model import train_and_compare_models
            train_and_compare_models()

        _MODEL = joblib.load(MODEL_PATH)

        if os.path.exists(COLUMNS_PATH):
            with open(COLUMNS_PATH, "r") as f:
                _FEATURE_COLS = json.load(f)
        else:
            _FEATURE_COLS = FEATURE_COLUMNS
    return _MODEL, _FEATURE_COLS


def get_model_metadata() -> Dict[str, Any]:
    """
    Returns training metadata and model metrics from training_metrics.json if available.
    """
    if os.path.exists(METRICS_PATH):
        try:
            with open(METRICS_PATH, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "best_model": "Random Forest Classifier",
        "classes": ["Benign", "Malicious", "Phishing", "Suspicious"],
        "feature_count": len(FEATURE_COLUMNS),
        "total_samples": 80,
    }


def predict_url(url: str) -> Dict[str, Any]:
    """
    Analyzes and classifies a single URL.
    Returns prediction label, confidence score, class probability distribution,
    extracted feature values, and feature DataFrame.
    """
    clf, feature_cols = get_model()
    feat_dict = extract_features_dict(url)
    feat_df = pd.DataFrame([feat_dict], columns=feature_cols)

    # Class predictions and probability distribution
    pred_label = clf.predict(feat_df)[0]
    classes = list(clf.classes_)

    if hasattr(clf, "predict_proba"):
        probs = clf.predict_proba(feat_df)[0]
        prob_dict = {str(c): round(float(p), 4) for c, p in zip(classes, probs)}
        confidence = float(np.max(probs))
    else:
        prob_dict = {str(c): (1.0 if c == pred_label else 0.0) for c in classes}
        confidence = 0.95

    # Threat probability is sum of phishing, malicious, and suspicious probabilities
    threat_prob = 1.0 - prob_dict.get("Benign", 0.0)

    return {
        "url": url,
        "prediction": pred_label,
        "confidence": round(confidence, 4),
        "threat_probability": round(threat_prob, 4),
        "probabilities": prob_dict,
        "classes": classes,
        "features": feat_dict,
        "features_df": feat_df,
    }


def batch_predict(urls: List[str]) -> List[Dict[str, Any]]:
    """
    Analyzes and classifies a batch of URLs.
    """
    clf, feature_cols = get_model()
    feat_df = batch_extract_features(urls)

    preds = clf.predict(feat_df)
    classes = list(clf.classes_)
    if hasattr(clf, "predict_proba"):
        probs = clf.predict_proba(feat_df)
    else:
        probs = None

    results = []
    for i, url in enumerate(urls):
        pred_label = preds[i]
        if probs is not None:
            url_probs = {str(c): round(float(p), 4) for c, p in zip(classes, probs[i])}
            conf = float(np.max(probs[i]))
        else:
            url_probs = {str(c): (1.0 if c == pred_label else 0.0) for c in classes}
            conf = 0.95

        threat_p = 1.0 - url_probs.get("Benign", 0.0)
        row_feat = feat_df.iloc[[i]]

        results.append({
            "url": url,
            "prediction": pred_label,
            "confidence": round(conf, 4),
            "threat_probability": round(threat_p, 4),
            "probabilities": url_probs,
            "classes": classes,
            "features": row_feat.iloc[0].to_dict(),
            "features_df": row_feat,
        })

    return results
