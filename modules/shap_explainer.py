"""
Explainable AI (XAI) - SHAP Explanation Module
Generates SHAP value explanations, risk contribution rankings, human-readable
SOC analyst narratives, and interactive Plotly visualizations.
"""

from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import shap

from modules.ml_model import get_model

_EXPLAINER = None

FEATURE_HUMAN_NAMES = {
    "url_length": "Overall URL Length",
    "domain_length": "Domain Name Length",
    "num_dots": "Dot Count (.)",
    "num_hyphens": "Hyphen Count (-)",
    "num_underscores": "Underscore Count (_)",
    "num_digits": "Digit Count",
    "num_special_chars": "Special Character Count",
    "num_subdomains": "Nested Subdomain Count",
    "is_ip_address": "Direct IP Address Host",
    "has_https": "HTTPS Protocol Usage",
    "has_suspicious_keywords": "Suspicious Security Keywords",
    "is_shortened": "URL Shortener Service",
    "has_at_symbol": "Embedded @ Symbol",
    "has_unusual_port": "Non-Standard Port",
    "has_encoded_chars": "Hex/URL Encoded Chars",
    "excessive_redirect_signs": "Redirect Target Parameters",
    "suspicious_tld": "High-Risk Top-Level Domain",
    "domain_entropy": "Domain Randomness (Entropy)",
    "brand_impersonation": "Brand Impersonation Signature",
    "suspicious_query_params": "Sensitive Query Parameters",
}


def get_explainer():
    """
    Lazy loads and caches the SHAP TreeExplainer for the trained model.
    """
    global _EXPLAINER
    if _EXPLAINER is None:
        model, _ = get_model()
        _EXPLAINER = shap.TreeExplainer(model)
    return _EXPLAINER


def explain_prediction(features_df: pd.DataFrame, predicted_label: str) -> Dict[str, Any]:
    """
    Computes SHAP values and builds explanation structures for the given URL features.
    """
    model, feature_cols = get_model()
    explainer = get_explainer()

    # shap_values shape for multi-class: list of ndarrays [n_samples, n_features] or (n_samples, n_features, n_classes)
    raw_shap = explainer.shap_values(features_df)
    classes = list(model.classes_)

    # Identify the index for the target class
    if predicted_label in classes:
        target_idx = classes.index(predicted_label)
    else:
        # Default to first non-benign class or class 0
        target_idx = 0

    if isinstance(raw_shap, list):
        class_shap_values = raw_shap[target_idx][0]
    elif len(raw_shap.shape) == 3:
        class_shap_values = raw_shap[0, :, target_idx]
    else:
        class_shap_values = raw_shap[0]

    feature_values = features_df.iloc[0].to_dict()

    contributions = []
    for col, val, shap_val in zip(feature_cols, features_df.iloc[0], class_shap_values):
        human_name = FEATURE_HUMAN_NAMES.get(col, col)
        contributions.append({
            "feature": col,
            "human_name": human_name,
            "value": float(val),
            "shap_value": float(shap_val),
            "abs_impact": abs(float(shap_val)),
            "direction": "Increases Risk" if shap_val > 0 else "Decreases Risk",
        })

    # Sort by absolute impact
    contributions.sort(key=lambda x: x["abs_impact"], reverse=True)

    risk_increasing = [c for c in contributions if c["shap_value"] > 0]
    risk_decreasing = [c for c in contributions if c["shap_value"] < 0]

    # Generate Plain-Language Analyst Narrative
    narrative = generate_analyst_narrative(predicted_label, feature_values, risk_increasing, risk_decreasing)

    return {
        "predicted_class": predicted_label,
        "contributions": contributions,
        "risk_increasing": risk_increasing,
        "risk_decreasing": risk_decreasing,
        "narrative": narrative,
        "feature_values": feature_values,
    }


def generate_analyst_narrative(
    pred_label: str,
    feat_values: Dict[str, Any],
    increasing: List[Dict[str, Any]],
    decreasing: List[Dict[str, Any]]
) -> str:
    """
    Creates an intuitive, human-understandable explanation of the model's decision.
    """
    if pred_label == "Benign":
        reasons = []
        if feat_values.get("has_https", 0) == 1:
            reasons.append("valid HTTPS encryption")
        if feat_values.get("brand_impersonation", 0) == 0:
            reasons.append("no brand typosquatting")
        if feat_values.get("suspicious_tld", 0) == 0:
            reasons.append("established standard top-level domain")
        if feat_values.get("num_subdomains", 0) <= 1:
            reasons.append("normal domain structure with minimal subdomains")
        
        detail = ", ".join(reasons) if reasons else "clean lexical structure and absence of malicious indicators"
        return (
            f"This URL was classified as **Benign** with high confidence. The model recognized {detail}, "
            f"and did not identify anomalous obfuscation techniques."
        )

    # For Phishing, Malicious, or Suspicious
    reasons = []
    if feat_values.get("brand_impersonation", 0) == 1:
        reasons.append("signs of brand impersonation/typosquatting")
    if feat_values.get("is_ip_address", 0) == 1:
        reasons.append("using a raw numerical IP address instead of a registered domain")
    if feat_values.get("has_https", 0) == 0:
        reasons.append("lack of HTTPS encryption (insecure HTTP)")
    if feat_values.get("has_suspicious_keywords", 0) == 1:
        reasons.append("presence of sensitive authentication/billing keywords")
    if feat_values.get("suspicious_tld", 0) == 1:
        reasons.append("a high-abuse, untrusted top-level domain")
    if feat_values.get("num_subdomains", 0) >= 2:
        reasons.append(f"excessive nested subdomains ({feat_values.get('num_subdomains')} levels)")
    if feat_values.get("is_shortened", 0) == 1:
        reasons.append("use of a URL shortening service to mask the real destination")
    if feat_values.get("excessive_redirect_signs", 0) == 1:
        reasons.append("open redirect patterns in URL parameters")
    if feat_values.get("domain_entropy", 0) > 3.8:
        reasons.append(f"unusually high domain randomness (entropy {feat_values.get('domain_entropy'):.2f}), typical of algorithmically generated domains (DGA)")

    if not reasons and increasing:
        top_reasons = [item["human_name"].lower() for item in increasing[:3]]
        reasons = [f"atypical {r}" for r in top_reasons]

    formatted_reasons = ", ".join(reasons[:-1]) + f", and {reasons[-1]}" if len(reasons) > 1 else (reasons[0] if reasons else "suspicious heuristic markers")

    return (
        f"This URL was flagged as **{pred_label}** primarily due to {formatted_reasons}. "
        f"These attributes align strongly with patterns observed in malicious credential theft and malware delivery campaigns."
    )


def create_shap_bar_chart(contributions: List[Dict[str, Any]], top_n: int = 10) -> go.Figure:
    """
    Renders an interactive Plotly horizontal bar chart of feature impacts.
    """
    top_items = contributions[:top_n]
    # Reverse so top item is at the top of the horizontal bar chart
    top_items = top_items[::-1]

    names = [item["human_name"] for item in top_items]
    shap_vals = [item["shap_value"] for item in top_items]
    colors = ["#ef4444" if val > 0 else "#10b981" for val in shap_vals]

    fig = go.Figure(
        go.Bar(
            x=shap_vals,
            y=names,
            orientation="h",
            marker=dict(color=colors),
            text=[f"{val:+.3f}" for val in shap_vals],
            textposition="auto",
        )
    )

    fig.update_layout(
        title="SHAP Feature Importance & Risk Contribution",
        title_font=dict(size=14, color="#38bdf8"),
        xaxis=dict(
            title="SHAP Value (Impact on Prediction)",
            gridcolor="#1e293b",
            zerolinecolor="#475569",
            color="#94a3b8",
        ),
        yaxis=dict(
            gridcolor="#1e293b",
            color="#cbd5e1",
        ),
        paper_bgcolor="#0f172a",
        plot_bgcolor="#0f172a",
        margin=dict(l=20, r=20, t=40, b=20),
        height=340,
    )
    return fig


def create_shap_waterfall_chart(contributions: List[Dict[str, Any]], top_n: int = 8) -> go.Figure:
    """
    Renders an interactive Plotly waterfall chart depicting cumulative risk buildup.
    """
    top_items = contributions[:top_n]
    names = [item["human_name"] for item in top_items]
    values = [item["shap_value"] for item in top_items]

    fig = go.Figure(
        go.Waterfall(
            name="Risk Factors",
            orientation="v",
            measure=["relative"] * len(values),
            x=names,
            textposition="outside",
            text=[f"{v:+.2f}" for v in values],
            y=values,
            connector={"line": {"color": "#64748b"}},
            decreasing={"marker": {"color": "#10b981"}},
            increasing={"marker": {"color": "#ef4444"}},
        )
    )

    fig.update_layout(
        title="Cumulative Risk Buildup (SHAP Waterfall)",
        title_font=dict(size=14, color="#38bdf8"),
        xaxis=dict(
            tickangle=-30,
            gridcolor="#1e293b",
            color="#cbd5e1",
        ),
        yaxis=dict(
            title="Net SHAP Contribution",
            gridcolor="#1e293b",
            zerolinecolor="#475569",
            color="#94a3b8",
        ),
        paper_bgcolor="#0f172a",
        plot_bgcolor="#0f172a",
        margin=dict(l=20, r=20, t=40, b=50),
        height=340,
    )
    return fig
