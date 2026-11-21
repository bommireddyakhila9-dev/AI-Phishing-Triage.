"""
SOC Overview Dashboard (Page 1)
Displays system metrics, threat distribution charts, recent triage activity, and telemetry.
"""

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from modules.database import get_metrics_summary, get_recent_analyses
from modules.ui_common import load_custom_css, render_header, render_metric_card, require_auth

load_custom_css()
require_auth()

render_header("SOC Threat Intelligence & Triage Dashboard", "High-level overview of analyzed links, active threat vectors, and incident metrics.")

metrics = get_metrics_summary()

# Top KPI Metric Cards
k1, k2, k3, k4, k5, k6 = st.columns(6)
with k1:
    render_metric_card("Analyzed URLs", str(metrics["total_analyzed"]), "All Time", "badge-low")
with k2:
    render_metric_card("Phishing", str(metrics["phishing_count"]), "Credential Theft", "badge-high")
with k3:
    render_metric_card("Malicious", str(metrics["malicious_count"]), "Payload Sites", "badge-critical")
with k4:
    render_metric_card("Suspicious", str(metrics["suspicious_count"]), "Anomalous", "badge-suspicious")
with k5:
    render_metric_card("Critical Alerts", str(metrics["critical_incidents"]), "P1 Incidents", "badge-critical")
with k6:
    render_metric_card("Detection Rate", f"{metrics['detection_rate']}%", "Threat Ratio", "badge-moderate")

st.markdown("<br>", unsafe_allow_html=True)

# Charts Row
c_chart1, c_chart2 = st.columns(2)

with c_chart1:
    st.markdown("#### 🎯 Classification Distribution")
    pred_data = metrics.get("prediction_distribution", {})
    if pred_data:
        labels = list(pred_data.keys())
        values = list(pred_data.values())
        color_map = {
            "Benign": "#10b981",
            "Phishing": "#f87171",
            "Malicious": "#ef4444",
            "Suspicious": "#fb923c",
        }
        colors = [color_map.get(l, "#06b6d4") for l in labels]

        fig_pie = go.Figure(
            data=[
                go.Pie(
                    labels=labels,
                    values=values,
                    hole=0.5,
                    marker=dict(colors=colors, line=dict(color="#0f172a", width=2)),
                    textinfo="label+percent",
                )
            ]
        )
        fig_pie.update_layout(
            paper_bgcolor="#0f172a",
            plot_bgcolor="#0f172a",
            font=dict(color="#cbd5e1"),
            margin=dict(l=10, r=10, t=20, b=20),
            height=300,
            showlegend=True,
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    else:
        st.info("No URL classification records available yet. Analyze a URL in the Scanner to populate telemetry.")

with c_chart2:
    st.markdown("#### ⚡ Risk Severity Breakdown")
    sev_data = metrics.get("severity_distribution", {})
    if sev_data:
        sev_categories = ["Low Risk", "Moderate Risk", "Suspicious", "High Risk", "Critical Risk"]
        sev_counts = [sev_data.get(cat, 0) for cat in sev_categories]
        sev_colors = ["#10b981", "#f59e0b", "#fb923c", "#f87171", "#ef4444"]

        fig_bar = go.Figure(
            go.Bar(
                x=sev_categories,
                y=sev_counts,
                marker=dict(color=sev_colors),
                text=sev_counts,
                textposition="auto",
            )
        )
        fig_bar.update_layout(
            paper_bgcolor="#0f172a",
            plot_bgcolor="#0f172a",
            font=dict(color="#cbd5e1"),
            xaxis=dict(gridcolor="#1e293b", color="#94a3b8"),
            yaxis=dict(gridcolor="#1e293b", color="#94a3b8"),
            margin=dict(l=10, r=10, t=20, b=20),
            height=300,
        )
        st.plotly_chart(fig_bar, use_container_width=True)
    else:
        st.info("Severity breakdown will display once initial scans are executed.")

# Recent URL Analyses Data Table
st.markdown("---")
st.markdown("### 📋 Recent URL Triage Activity")

recent_list = get_recent_analyses(limit=25)
if recent_list:
    df_recent = pd.DataFrame(recent_list)
    df_display = df_recent[[
        "id", "defanged_url", "prediction", "confidence", "risk_score", "risk_category", "analysis_timestamp", "analyzed_by"
    ]].copy()

    df_display["confidence"] = (df_display["confidence"] * 100).round(1).astype(str) + "%"
    df_display.columns = [
        "ID", "Target (Defanged)", "Prediction", "Confidence", "Score", "Severity", "Timestamp (UTC)", "Analyst"
    ]

    st.dataframe(df_display, use_container_width=True, hide_index=True)
else:
    st.info("No triage activity recorded in the database yet. Head to the **URL Scanner** to run your first URL investigation.")
