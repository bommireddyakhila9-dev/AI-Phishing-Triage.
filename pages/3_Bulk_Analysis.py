"""
Bulk URL Analysis & CSV Triage Module (Page 3)
Supports batch ingestion via CSV file upload or multi-line text input,
batch ML inference, progress tracking, dynamic filtering, and CSV export.
"""

from datetime import datetime
import io
import pandas as pd
import streamlit as st

from modules.feature_extraction import extract_features_dict
from modules.ml_model import batch_predict
from modules.risk_scoring import compute_heuristic_score, get_risk_category
from modules.ui_common import load_custom_css, render_header, render_metric_card, require_auth
from modules.url_validator import defang_url, is_valid_url

load_custom_css()
require_auth()

render_header("Bulk URL Analysis & Batch Triage", "High-throughput security classification, risk scoring, and export for enterprise feeds.")

tab_csv, tab_text = st.tabs(["📁 Upload CSV File", "📝 Paste URL List"])

urls_to_process = []

with tab_csv:
    st.markdown("##### Upload CSV File Containing URL Column")
    uploaded_file = st.file_uploader("Choose a CSV file", type=["csv"], help="Maximum 100 URLs per batch for performance.")

    if uploaded_file is not None:
        try:
            raw_df = pd.read_csv(uploaded_file)
            st.success(f"File uploaded successfully! Loaded {len(raw_df)} rows.")

            # Auto-detect URL column
            candidate_cols = [c for c in raw_df.columns if any(term in c.lower() for term in ["url", "link", "uri", "site", "domain", "target"])]
            default_col = candidate_cols[0] if candidate_cols else raw_df.columns[0]

            selected_col = st.selectbox("Select URL Column:", raw_df.columns, index=list(raw_df.columns).index(default_col))

            candidate_urls = raw_df[selected_col].dropna().astype(str).tolist()
            # De-duplicate while preserving order
            seen = set()
            deduped = []
            for u in candidate_urls:
                u_clean = u.strip()
                if u_clean and u_clean not in seen:
                    seen.add(u_clean)
                    deduped.append(u_clean)

            if len(deduped) > 100:
                st.warning(f"Batch contains {len(deduped)} URLs. Limiting analysis to first 100 entries.")
                urls_to_process = deduped[:100]
            else:
                urls_to_process = deduped

            st.info(f"Target count: **{len(urls_to_process)} unique URLs** ready for analysis.")
        except Exception as exc:
            st.error(f"Failed to parse CSV file: {str(exc)}")

with tab_text:
    st.markdown("##### Paste URLs (One per line)")
    sample_text = (
        "http://paypal-security-verification-login.com.account-update.xyz/signin\n"
        "https://www.google.com\n"
        "http://appleid-support-alert.com-recovery.icu/login?id=9928\n"
        "http://192.168.1.105:8080/payload.exe\n"
        "https://github.com/torvalds/linux\n"
        "http://bit.ly/3x8yZ1_unknown_redirect_auth"
    )
    pasted_text = st.text_area("Input URLs:", value=sample_text if not urls_to_process else "", height=150)
    if not urls_to_process and pasted_text.strip():
        lines = [line.strip() for line in pasted_text.strip().split("\n") if line.strip()]
        # De-duplicate
        seen = set()
        deduped = []
        for line in lines:
            if line not in seen:
                seen.add(line)
                deduped.append(line)
        urls_to_process = deduped[:100]

if urls_to_process:
    if st.button(f"⚡ Start Batch Triage ({len(urls_to_process)} URLs)", type="primary"):
        progress_bar = st.progress(0)
        status_text = st.empty()

        results_list = []
        total = len(urls_to_process)

        # Batch prediction with ML model
        status_text.text("Executing batch ML classification...")
        ml_batch_results = batch_predict(urls_to_process)

        for i, item in enumerate(ml_batch_results):
            url = item["url"]
            pred = item["prediction"]
            conf = item["confidence"]
            threat_p = item["threat_probability"]
            feat = item["features"]

            # Compute combined risk score
            h_score = compute_heuristic_score(feat)
            ml_score = int(round(threat_p * 100))
            composite_score = int(round((0.55 * ml_score) + (0.45 * h_score)))
            cat_info = get_risk_category(composite_score)

            key_indicator = "Standard"
            if feat.get("brand_impersonation"):
                key_indicator = "Brand Impersonation"
            elif feat.get("is_ip_address"):
                key_indicator = "IP Address Host"
            elif feat.get("suspicious_tld"):
                key_indicator = "Untrusted TLD"
            elif feat.get("has_suspicious_keywords"):
                key_indicator = "Credential Keywords"

            results_list.append({
                "Original URL": url,
                "Defanged URL": defang_url(url),
                "Classification": pred,
                "Confidence (%)": round(conf * 100, 1),
                "Risk Score": composite_score,
                "Risk Category": cat_info["category"],
                "Key Indicator": key_indicator,
                "HTTPS": "Yes" if feat.get("has_https") else "No",
            })

            progress_bar.progress((i + 1) / total)

        status_text.text("Batch analysis completed successfully!")
        st.session_state["bulk_results"] = results_list

# Display Results if available
if "bulk_results" in st.session_state and st.session_state["bulk_results"]:
    results_df = pd.DataFrame(st.session_state["bulk_results"])

    st.markdown("---")
    st.markdown("### 📊 Batch Telemetry & Metrics")

    # Metrics
    total_scanned = len(results_df)
    threats_detected = len(results_df[results_df["Classification"].str.lower() != "benign"])
    critical_detected = len(results_df[results_df["Risk Score"] >= 80])

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        render_metric_card("Processed URLs", str(total_scanned), "Batch Total", "badge-low")
    with m2:
        render_metric_card("Threats Flagged", str(threats_detected), "Non-Benign", "badge-high")
    with m3:
        render_metric_card("Critical Risks", str(critical_detected), "Score ≥ 80", "badge-critical")
    with m4:
        detection_pct = round((threats_detected / total_scanned) * 100, 1) if total_scanned else 0
        render_metric_card("Batch Threat Rate", f"{detection_pct}%", "Ratio", "badge-moderate")

    st.markdown("<br>", unsafe_allow_html=True)

    # Interactive Filter Controls
    st.markdown("##### 🔍 Filter & Sort Results")
    fc1, fc2, fc3 = st.columns(3)

    with fc1:
        classes_available = ["All"] + sorted(list(results_df["Classification"].unique()))
        filter_class = st.selectbox("Filter by Classification:", classes_available)

    with fc2:
        cats_available = ["All"] + sorted(list(results_df["Risk Category"].unique()))
        filter_cat = st.selectbox("Filter by Risk Category:", cats_available)

    with fc3:
        min_score = st.slider("Minimum Risk Score:", 0, 100, 0)

    filtered_df = results_df.copy()
    if filter_class != "All":
        filtered_df = filtered_df[filtered_df["Classification"] == filter_class]
    if filter_cat != "All":
        filtered_df = filtered_df[filtered_df["Risk Category"] == filter_cat]
    filtered_df = filtered_df[filtered_df["Risk Score"] >= min_score]

    # Render Table
    st.dataframe(
        filtered_df[[
            "Defanged URL", "Classification", "Confidence (%)", "Risk Score", "Risk Category", "Key Indicator", "HTTPS"
        ]],
        use_container_width=True,
        hide_index=True,
    )

    # CSV Export Button
    csv_buffer = io.StringIO()
    filtered_df.to_csv(csv_buffer, index=False)
    st.download_button(
        label="📥 Download Triaged Results as CSV",
        data=csv_buffer.getvalue(),
        file_name=f"SOAR_Batch_Triage_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
        type="primary",
    )
