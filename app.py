"""
AI Phishing & Malicious URL Triage Dashboard (SOAR Lite)
Main Application Entrypoint & Authentication Gateway
"""

import os
import streamlit as st

# Configure page metadata
st.set_page_config(
    page_title="AI Phishing & Malicious URL Triage Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

from modules.authentication import authenticate_user, register_user, seed_default_admin
from modules.database import get_metrics_summary, init_db
from modules.ui_common import load_custom_css, render_header, render_metric_card

# Initialize database schema and seed default users
init_db()
seed_default_admin()
load_custom_css()

# Session State Initialization
if "user" not in st.session_state:
    st.session_state["user"] = None
if "active_url_scan" not in st.session_state:
    st.session_state["active_url_scan"] = None


# Sidebar Navigation & Authentication Status
with st.sidebar:
    st.markdown("### 🛡️ **SOAR Lite**")
    st.caption("AI-Powered Threat Triage & Incident Response")
    st.markdown("---")

    if st.session_state["user"]:
        u = st.session_state["user"]
        st.success(f"**Analyst:** `{u.get('username')}`")
        st.info(f"**Role:** {u.get('role')}")
        if st.button("🚪 Log Out", use_container_width=True):
            st.session_state["user"] = None
            st.session_state["active_url_scan"] = None
            st.rerun()
    else:
        st.warning("🔒 Status: Unauthenticated")
        st.caption("Please log in using your analyst credentials.")

    st.markdown("---")
    st.markdown("#### ⚡ System Telemetry")
    st.markdown("- **Engine:** Random Forest + SHAP")
    st.markdown("- **Threat Feeds:** VirusTotal & URLhaus")
    st.markdown("- **Orchestration:** SOAR Lite Playbooks")
    st.markdown("- **LLM:** Gemini API / Local Analyst")


# Main Display
if not st.session_state["user"]:
    render_header("SOC Analyst Portal", "Authenticate to access AI Phishing & Malicious URL Triage Dashboard")

    col_center1, col_center2, col_center3 = st.columns([1, 2, 1])
    with col_center2:
        tab_login, tab_register = st.tabs(["🔐 Analyst Login", "📝 New Registration"])

        with tab_login:
            st.markdown("#### Sign In to SOC Workspace")
            login_user = st.text_input("Username", key="login_username")
            login_pass = st.text_input("Password", type="password", key="login_password")

            if st.button("Log In", type="primary", use_container_width=True):
                if login_user and login_pass:
                    success, user_data, msg = authenticate_user(login_user, login_pass)
                    if success:
                        st.session_state["user"] = user_data
                        st.success("Authentication successful! Redirecting...")
                        st.rerun()
                    else:
                        st.error(f"Authentication Failed: {msg}")
                else:
                    st.warning("Please provide both username and password.")

            st.markdown("---")
            st.info(
                "💡 **Default Analyst Credentials for Evaluation:**\n\n"
                "- Username: `analyst`\n"
                "- Password: `socAnalyst2026!`\n\n"
                "*(Or sign up with a new account in the tab above)*"
            )

        with tab_register:
            st.markdown("#### Register SOC Analyst Account")
            reg_user = st.text_input("Choose Username", key="reg_username")
            reg_pass = st.text_input("Choose Password", type="password", key="reg_password")
            reg_role = st.selectbox("Role", ["Security Analyst", "Senior SOC Analyst", "Incident Responder", "Threat Hunter"])

            if st.button("Create Account", use_container_width=True):
                if reg_user and reg_pass:
                    ok, reg_msg = register_user(reg_user, reg_pass, role=reg_role)
                    if ok:
                        st.success(f"{reg_msg} You may now sign in.")
                    else:
                        st.error(reg_msg)
                else:
                    st.warning("Please fill in all registration fields.")

else:
    # Authenticated Landing Page
    user = st.session_state["user"]
    render_header(
        f"Welcome to SOAR Lite, {user.get('username').title()}",
        "AI-Powered Malicious URL Triage, Explainable Threat Detection & Automated Incident Response"
    )

    metrics = get_metrics_summary()

    # KPI Summary Row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        render_metric_card("Total URLs Analyzed", str(metrics["total_analyzed"]), "Database Records", "badge-low")
    with c2:
        render_metric_card("Phishing URLs", str(metrics["phishing_count"]), "Active Lures", "badge-high")
    with c3:
        render_metric_card("Malware Endpoints", str(metrics["malicious_count"]), "High Danger", "badge-critical")
    with c4:
        render_metric_card("Threat Detection Rate", f"{metrics['detection_rate']}%", "Threat Ratio", "badge-moderate")

    st.markdown("<br>", unsafe_allow_html=True)

    # Navigation Grid
    st.markdown("### 🚀 Fast Navigation & Operation Centers")
    nav_c1, nav_c2, nav_c3 = st.columns(3)

    with nav_c1:
        st.markdown(
            """
            <div class="cyber-panel">
                <div class="cyber-panel-title">🔍 URL Scanner</div>
                <p style="color:#94a3b8; font-size:0.9rem;">
                    Perform single URL deep inspection, SHAP explainable ML classification, multi-vendor threat intel, and generate AI incident reports.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Launch URL Scanner", use_container_width=True):
            st.switch_page("pages/2_URL_Scanner.py")

    with nav_c2:
        st.markdown(
            """
            <div class="cyber-panel">
                <div class="cyber-panel-title">📊 SOC Dashboard</div>
                <p style="color:#94a3b8; font-size:0.9rem;">
                    View live cybersecurity metrics, severity breakdowns, threat timelines, and statistical distributions of all triaged links.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Open Dashboard", use_container_width=True):
            st.switch_page("pages/1_Dashboard.py")

    with nav_c3:
        st.markdown(
            """
            <div class="cyber-panel">
                <div class="cyber-panel-title">📁 Bulk URL Analysis</div>
                <p style="color:#94a3b8; font-size:0.9rem;">
                    Upload CSV batches or paste URL lists for high-throughput automated classification, risk scoring, and CSV export.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Open Bulk Analyzer", use_container_width=True):
            st.switch_page("pages/3_Bulk_Analysis.py")

    nav_c4, nav_c5, nav_c6 = st.columns(3)

    with nav_c4:
        st.markdown(
            """
            <div class="cyber-panel">
                <div class="cyber-panel-title">🌐 Threat Intelligence</div>
                <p style="color:#94a3b8; font-size:0.9rem;">
                    Query VirusTotal engine detections, URLhaus malware payloads, WHOIS registrar data, and DNS infrastructure records.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Explore Threat Intel", use_container_width=True):
            st.switch_page("pages/4_Threat_Intelligence.py")

    with nav_c5:
        st.markdown(
            """
            <div class="cyber-panel">
                <div class="cyber-panel-title">🚨 Incident Management</div>
                <p style="color:#94a3b8; font-size:0.9rem;">
                    Manage active security incidents, assign priority, review SOAR playbooks, update containment status, and export reports.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Manage Incidents", use_container_width=True):
            st.switch_page("pages/5_Incident_Management.py")

    with nav_c6:
        st.markdown(
            """
            <div class="cyber-panel">
                <div class="cyber-panel-title">🤖 AI Security Analyst</div>
                <p style="color:#94a3b8; font-size:0.9rem;">
                    Engage in contextual chatbot discussions with the SOC AI analyst regarding triaged threats, MITRE tactics, and remediation.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Chat with AI Analyst", use_container_width=True):
            st.switch_page("pages/6_AI_Analyst.py")
