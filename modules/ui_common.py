"""
Shared UI Components & Streamlit Helpers
Provides styling injection, header rendering, auth guard, and metric card helpers.
"""

import os
from typing import Optional
import streamlit as st
from modules.authentication import seed_default_admin
from modules.database import init_db

# Initialize database and seed admin on first import
init_db()
seed_default_admin()


def load_custom_css():
    """
    Loads custom cybersecurity CSS into the Streamlit app.
    """
    css_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets", "styles.css")
    if os.path.exists(css_path):
        with open(css_path, "r", encoding="utf-8") as f:
            css = f.read()
        st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


def require_auth() -> bool:
    """
    Guards pages, redirecting unauthenticated users to the main login portal.
    """
    if "user" not in st.session_state or not st.session_state["user"]:
        load_custom_css()
        render_header("Security Authentication Required", "Please log in via the Home portal to access this SOC module.")
        st.warning("⚠️ Access Restricted: Please authenticate to proceed.")
        col1, col2 = st.columns([1, 4])
        with col1:
            if st.button("🔐 Go to Login"):
                st.switch_page("app.py")
        st.stop()
        return False
    return True


def render_header(title: str, subtitle: str = ""):
    """
    Renders top cybersecurity header banner.
    """
    user_str = ""
    if "user" in st.session_state and st.session_state["user"]:
        u = st.session_state["user"]
        user_str = f"<div style='text-align:right;'><span style='color:#38bdf8; font-weight:600;'>👤 {u.get('username')}</span><br><span style='font-size:0.75rem; color:#94a3b8;'>{u.get('role')}</span></div>"

    html = f"""
    <div class="soc-header">
        <div>
            <div class="soc-header-title">🛡️ {title}</div>
            <div class="soc-header-subtitle">{subtitle}</div>
        </div>
        {user_str}
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)


def render_metric_card(label: str, value: str, badge_text: str = "", badge_class: str = "badge-low"):
    """
    Renders custom styled HTML KPI metric card.
    """
    badge_html = f'<div class="soc-metric-badge {badge_class}">{badge_text}</div>' if badge_text else ''
    html = f"""
    <div class="soc-metric-card">
        <div class="soc-metric-label">{label}</div>
        <div class="soc-metric-value">{value}</div>
        {badge_html}
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)
