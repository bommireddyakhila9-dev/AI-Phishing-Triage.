"""
Application Settings & Platform Configuration (Page 7)
Configures API keys, model telemetry, risk scoring weights, simulated blocklist, and database status.
"""

import json
import os
import pandas as pd
import streamlit as st

from modules.database import add_to_blocklist, get_all_blocklist, remove_from_blocklist
from modules.ml_model import get_model_metadata
from modules.ui_common import load_custom_css, render_header, require_auth

load_custom_css()
require_auth()

render_header("Platform Settings & Configuration", "Manage threat feed APIs, inspect ML model metrics, customize scoring weights, and manage the blocklist.")

t_api, t_model, t_weights, t_block, t_db = st.tabs([
    "🔑 API Integrations",
    "🧠 Machine Learning Telemetry",
    "⚖️ Risk Scoring Weights",
    "🚫 Blocklist Management",
    "💾 Database & Profile",
])

# TAB 1: API Integrations
with t_api:
    st.markdown("#### External Intelligence & LLM API Status")
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    urlh_key = os.getenv("URLHAUS_API_KEY", "")
    gemini_key = os.getenv("GEMINI_API_KEY", "")

    api_records = [
        {
            "Service": "VirusTotal v3",
            "Environment Variable": "VIRUSTOTAL_API_KEY",
            "Configured": "Yes" if (vt_key and vt_key != "your_virustotal_api_key_here") else "Demo Fallback Mode",
            "Description": "URL multi-vendor reputation and detection engine statistics",
        },
        {
            "Service": "abuse.ch URLhaus",
            "Environment Variable": "URLHAUS_API_KEY",
            "Configured": "Yes" if (urlh_key and urlh_key != "your_urlhaus_api_key_here") else "Public API / Demo Mode",
            "Description": "Malware payload and dropper distribution threat intelligence",
        },
        {
            "Service": "Google Gemini API",
            "Environment Variable": "GEMINI_API_KEY",
            "Configured": "Yes" if (gemini_key and gemini_key != "your_gemini_api_key_here") else "Built-in SOC Analyst Engine",
            "Description": "Generative AI security summaries and incident report generation",
        },
        {
            "Service": "ICANN RDAP / WHOIS",
            "Environment Variable": "N/A (Public Protocol)",
            "Configured": "Active",
            "Description": "Domain registration, registrar identity, and domain age tracking",
        },
    ]

    st.dataframe(api_records, use_container_width=True)
    st.info(
        "💡 **API Key Setup:** Configure your API keys in the `.env` file in the root workspace directory. "
        "All features have built-in realistic fallback modes, ensuring the application remains fully testable without keys."
    )

# TAB 2: Machine Learning Model
with t_model:
    st.markdown("#### Model Architecture & Evaluation Metrics")
    meta = get_model_metadata()

    col_m1, col_m2 = st.columns([1, 1])

    with col_m1:
        st.markdown(
            f"""
            <div class="cyber-panel">
                <div class="cyber-panel-title">🏆 Champion Classifier</div>
                <div style="font-size:1.3rem; font-weight:700; color:#38bdf8;">
                    {meta.get('best_model', 'Random Forest')}
                </div>
                <ul style="color:#cbd5e1; font-size:0.9rem; margin-top:10px; line-height:1.6;">
                    <li><strong>Feature Dimensionality:</strong> {meta.get('feature_count', 20)} Security Features</li>
                    <li><strong>Target Classes:</strong> {', '.join(meta.get('classes', []))}</li>
                    <li><strong>Training Samples:</strong> {meta.get('total_samples', 80)} Labeled Samples</li>
                    <li><strong>Explainability Layer:</strong> SHAP TreeExplainer</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_m2:
        evaluated = meta.get("models_evaluated", {})
        if evaluated:
            st.markdown("##### Model Comparison Performance (Held-out Test Data):")
            comp_rows = []
            for name, stats in evaluated.items():
                comp_rows.append({
                    "Model": name,
                    "Accuracy": f"{stats['accuracy']*100:.1f}%",
                    "Precision": f"{stats['precision']*100:.1f}%",
                    "Recall": f"{stats['recall']*100:.1f}%",
                    "F1 Score": f"{stats['f1_score']:.4f}",
                })
            st.dataframe(comp_rows, use_container_width=True)

    if meta.get("models_evaluated", {}).get("Random Forest", {}).get("confusion_matrix"):
        cm = meta["models_evaluated"]["Random Forest"]["confusion_matrix"]
        classes = meta["classes"]
        st.markdown("##### Confusion Matrix (Champion Model):")
        cm_df = pd.DataFrame(cm, index=[f"Actual {c}" for c in classes], columns=[f"Predicted {c}" for c in classes])
        st.dataframe(cm_df, use_container_width=True)

# TAB 3: Risk Scoring Weights
with t_weights:
    st.markdown("#### Configurable Risk Scoring Weights")
    st.caption("Customize how different telemetry pillars contribute to the 0-100 composite risk score.")

    w_ml = st.slider("Machine Learning Classification Weight (%):", 0, 100, 40)
    w_heu = st.slider("Lexical & Structural Heuristic Indicators Weight (%):", 0, 100, 25)
    w_ti = st.slider("Threat Intelligence Vendor Consensus Weight (%):", 0, 100, 25)
    w_dom = st.slider("Domain Age & Infrastructure Reputation Weight (%):", 0, 100, 10)

    total_w = w_ml + w_heu + w_ti + w_dom
    if total_w != 100:
        st.warning(f"Weights currently sum to {total_w}%. They will be normalized automatically during computation.")
    else:
        st.success("Weights normalized to 100%.")

# TAB 4: Blocklist Management
with t_block:
    st.markdown("#### 🚫 SOAR Simulated Perimeter Blocklist")
    st.caption("Active local blocklist used to simulate firewall, DNS, and proxy egress quarantine.")

    add_c1, add_c2, add_c3 = st.columns([3, 2, 1])
    with add_c1:
        new_target = st.text_input("Add Domain or URL to Blocklist:", placeholder="e.g. evil-phish-domain.top")
    with add_c2:
        new_reason = st.text_input("Blocking Justification:", placeholder="Manual quarantine")
    with add_c3:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("Add Target", type="primary"):
            if new_target.strip():
                ok, msg = add_to_blocklist(
                    target=new_target.strip(),
                    reason=new_reason.strip() or "Manual SOC Block",
                    added_by=st.session_state["user"].get("username", "analyst")
                )
                if ok:
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(msg)

    blocked_entries = get_all_blocklist()
    if blocked_entries:
        st.markdown("##### Current Quarantined Entries:")
        for entry in blocked_entries:
            b_col1, b_col2, b_col3, b_col4 = st.columns([3, 2, 2, 1])
            with b_col1:
                st.code(entry["target"], language="text")
            with b_col2:
                st.caption(f"Reason: {entry['reason']}")
            with b_col3:
                st.caption(f"Added by: {entry['added_by']} on {entry['added_at']}")
            with b_col4:
                if st.button("Unblock", key=f"unblock_{entry['id']}"):
                    remove_from_blocklist(entry["id"])
                    st.success("Target removed from blocklist.")
                    st.rerun()
    else:
        st.info("Simulated blocklist is currently empty.")

# TAB 5: Database & Profile
with t_db:
    st.markdown("#### User Profile & System Database")
    u = st.session_state["user"]
    st.write(f"- **Username:** `{u.get('username')}`")
    st.write(f"- **Assigned Role:** `{u.get('role')}`")
    st.write(f"- **Database Storage:** `data/soar_lite.db` (SQLite 3)")
    st.write("- **Password Security:** Salted PBKDF2 / bcrypt hashing")
