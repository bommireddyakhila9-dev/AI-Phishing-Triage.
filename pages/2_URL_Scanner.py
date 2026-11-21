"""
URL Deep Scanner & Triage Module (Page 2)
Performs single URL lexical feature extraction, ML classification, SHAP explanations,
multi-source threat intelligence lookup, composite risk scoring, and SOAR response.
"""

from datetime import datetime
import streamlit as st

from modules.ai_analyst import generate_ai_report
from modules.database import add_to_blocklist, create_incident, is_target_blocked, save_analysis
from modules.domain_intelligence import query_domain_intelligence
from modules.feature_extraction import extract_features_df, extract_features_dict
from modules.incident_manager import execute_soar_containment, get_playbook_recommendations
from modules.ml_model import predict_url
from modules.report_generator import generate_json_report, generate_markdown_report
from modules.risk_scoring import calculate_composite_risk_score, create_risk_gauge_chart
from modules.shap_explainer import create_shap_bar_chart, create_shap_waterfall_chart, explain_prediction
from modules.ui_common import load_custom_css, render_header, require_auth
from modules.url_validator import defang_url, is_safe_for_network, is_valid_url
from modules.urlhaus import query_urlhaus
from modules.virustotal import query_virustotal

load_custom_css()
require_auth()

render_header("URL Deep Scanner & SOAR Triage", "Comprehensive ML analysis, explainable SHAP diagnostics, and external threat enrichment.")

# Quick Demonstration Sample Presets
SAMPLE_PRESETS = {
    "-- Custom URL Input --": "",
    "Phishing Sample (PayPal Brand Impersonation)": "http://paypal-security-verification-login.com.account-update.xyz/signin",
    "Phishing Sample (Apple ID Verification Lure)": "http://appleid-support-alert.com-recovery.icu/login?id=9928",
    "Malware Sample (Direct IP Payload Dropper)": "http://192.168.1.105:8080/payload.exe",
    "Malware Sample (C2 Beacon Server)": "http://evil-c2-server-panel.xyz/beacon.php?cmd=exec",
    "Suspicious Sample (Shortened Redirect Lure)": "http://bit.ly/3x8yZ1_unknown_redirect_auth",
    "Legitimate Sample (GitHub)": "https://github.com/torvalds/linux",
    "Legitimate Sample (Google)": "https://www.google.com",
}

st.markdown("#### 🔍 URL Submission")
col_preset, col_scan_btn = st.columns([3, 1])

with col_preset:
    preset_choice = st.selectbox("Quick Test with Demonstration Samples:", list(SAMPLE_PRESETS.keys()))

default_input_val = SAMPLE_PRESETS[preset_choice] if preset_choice != "-- Custom URL Input --" else ""

url_input = st.text_input(
    "Enter URL for Security Inspection:",
    value=default_input_val,
    placeholder="e.g. http://secure-login-portal.top/verification",
    help="Enter an HTTP/HTTPS URL. Defanging is handled automatically for safety.",
)

col_run, col_clear = st.columns([1, 5])
with col_run:
    run_analysis = st.button("🚀 Analyze URL", type="primary", use_container_width=True)

if run_analysis and url_input.strip():
    raw_url = url_input.strip()

    # Step 1: URL Validation & SSRF Check
    valid, val_msg = is_valid_url(raw_url)
    if not valid:
        st.error(f"❌ Input Validation Error: {val_msg}")
        st.stop()

    safe_net, net_msg = is_safe_for_network(raw_url)
    if not safe_net:
        st.warning(f"⚠️ Security Policy Warning: {net_msg}")

    with st.spinner("Executing ML feature extraction, model inference, and threat intelligence telemetry..."):
        # 1. ML Prediction
        ml_res = predict_url(raw_url)

        # 2. SHAP Explanation
        shap_res = explain_prediction(ml_res["features_df"], ml_res["prediction"])

        # 3. Threat Intelligence
        vt_res = query_virustotal(raw_url)
        urlhaus_res = query_urlhaus(raw_url)
        domain_res = query_domain_intelligence(raw_url)

        # 4. Composite Risk Scoring
        risk_res = calculate_composite_risk_score(
            ml_result=ml_res,
            features=ml_res["features"],
            vt_result=vt_res,
            urlhaus_result=urlhaus_res,
            domain_intel=domain_res,
        )

        # 5. Persist into SQLite
        analyst_user = st.session_state["user"].get("username", "analyst")
        save_analysis(
            url=raw_url,
            defanged_url=defang_url(raw_url),
            prediction=ml_res["prediction"],
            confidence=ml_res["confidence"],
            risk_score=risk_res["risk_score"],
            risk_category=risk_res["risk_category"],
            threat_intel_summary=f"VT: {vt_res.get('malicious_count', 0)} mal | URLhaus: {urlhaus_res.get('threat', 'clean')}",
            analyzed_by=analyst_user,
        )

        # Save to session state for persistence across tab interactions
        st.session_state["active_url_scan"] = {
            "url": raw_url,
            "defanged_url": defang_url(raw_url),
            "ml_res": ml_res,
            "shap_res": shap_res,
            "vt_res": vt_res,
            "urlhaus_res": urlhaus_res,
            "domain_res": domain_res,
            "risk_res": risk_res,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "ai_report": None,
        }

# If an active scan is loaded
if st.session_state.get("active_url_scan"):
    scan = st.session_state["active_url_scan"]
    raw_url = scan["url"]
    safe_url = scan["defanged_url"]
    ml_res = scan["ml_res"]
    shap_res = scan["shap_res"]
    vt_res = scan["vt_res"]
    urlhaus_res = scan["urlhaus_res"]
    domain_res = scan["domain_res"]
    risk_res = scan["risk_res"]

    st.markdown("---")

    # Safe Defanged URL Indicator Banner
    st.markdown(
        f"""
        <div style="background-color:#111c33; border:1px solid #1e293b; padding:12px 18px; border-radius:8px; margin-bottom:18px;">
            <span style="color:#94a3b8; font-size:0.85rem; font-weight:600;">DEFANGED SAFE DISPLAY:</span><br>
            <span class="defanged-url">{safe_url}</span>
            <span style="float:right; font-size:0.8rem; color:#64748b;">Triaged: {scan['timestamp']}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Top Row: Verdict & Gauge
    c_verdict, c_gauge = st.columns([1, 1])

    with c_verdict:
        badge_cls = risk_res["badge_class"]
        pred_label = ml_res["prediction"]
        conf_pct = ml_res["confidence"] * 100

        st.markdown(
            f"""
            <div class="cyber-panel" style="min-height: 260px;">
                <div class="cyber-panel-title">🛡️ Classification Assessment</div>
                <div style="font-size: 2.2rem; font-weight: 800; color: {risk_res['color']}; margin-top: 10px;">
                    {pred_label}
                </div>
                <div style="margin-top: 6px;">
                    <span class="soc-metric-badge {badge_cls}" style="font-size:0.9rem; padding: 4px 12px;">
                        {risk_res['risk_category']} ({risk_res['risk_score']}/100)
                    </span>
                </div>
                <div style="margin-top: 18px; color: #94a3b8; font-size: 0.9rem;">
                    <strong>Model Confidence:</strong> <span style="color:#f8fafc;">{conf_pct:.1f}%</span><br>
                    <strong>Threat Probability:</strong> <span style="color:#f8fafc;">{ml_res['threat_probability']*100:.1f}%</span><br>
                    <strong>Architecture:</strong> Balanced Random Forest Classifier
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c_gauge:
        st.plotly_chart(
            create_risk_gauge_chart(risk_res["risk_score"], risk_res["risk_category"], risk_res["color"]),
            use_container_width=True,
        )

    # Four Core Investigative Tabs
    t_shap, t_intel, t_ai, t_soar = st.tabs([
        "🔍 Explainable AI (SHAP)",
        "🌐 Threat Intelligence",
        "🤖 AI Security Analyst",
        "⚡ SOAR Lite Response",
    ])

    # TAB 1: Explainable AI
    with t_shap:
        st.markdown("#### 🧠 SHAP Feature Diagnostics & Plain-Language Explanation")
        st.markdown(
            f"""
            <div style="background-color:#0f172a; border-left:4px solid #38bdf8; padding:12px 16px; border-radius:4px; margin-bottom:15px; color:#cbd5e1; font-size:0.92rem;">
                {shap_res['narrative']}
            </div>
            """,
            unsafe_allow_html=True,
        )

        c_wfall, c_bar = st.columns(2)
        with c_wfall:
            st.plotly_chart(create_shap_waterfall_chart(shap_res["contributions"]), use_container_width=True)
        with c_bar:
            st.plotly_chart(create_shap_bar_chart(shap_res["contributions"]), use_container_width=True)

        with st.expander("📊 Complete Extracted Feature Telemetry (20 Features)"):
            feat_items = [{"Feature": k, "Value": v} for k, v in ml_res["features"].items()]
            st.dataframe(feat_items, use_container_width=True)

    # TAB 2: Threat Intelligence
    with t_intel:
        st.markdown("#### 🌐 Multi-Source Threat Intelligence Findings")

        vt_c1, vt_c2 = st.columns(2)
        with vt_c1:
            st.markdown(
                f"""
                <div class="cyber-panel">
                    <div class="cyber-panel-title">🛡️ VirusTotal URL Reputation</div>
                    <div style="font-size:1.4rem; font-weight:700; color:{'#ef4444' if vt_res.get('malicious_count',0)>0 else '#10b981'};">
                        {vt_res.get('malicious_count', 0)} / {vt_res.get('total_engines', 0)} Engines Flagged
                    </div>
                    <p style="color:#94a3b8; font-size:0.85rem; margin-top:6px;">
                        {vt_res.get('status_message')}
                    </p>
                    <div style="font-size:0.82rem; color:#64748b;">
                        Reputation Score: {vt_res.get('reputation', 0)} | Simulated: {vt_res.get('is_simulated', False)}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with vt_c2:
            st.markdown(
                f"""
                <div class="cyber-panel">
                    <div class="cyber-panel-title">☣️ abuse.ch URLhaus Malware Database</div>
                    <div style="font-size:1.4rem; font-weight:700; color:{'#ef4444' if urlhaus_res.get('is_listed') else '#10b981'};">
                        {'MALWARE LISTED' if urlhaus_res.get('is_listed') else 'CLEAN / UNLISTED'}
                    </div>
                    <p style="color:#94a3b8; font-size:0.85rem; margin-top:6px;">
                        Threat Type: <strong>{urlhaus_res.get('threat', 'None')}</strong><br>
                        Tags: {', '.join(urlhaus_res.get('tags', [])) if urlhaus_res.get('tags') else 'None'}
                    </p>
                    <div style="font-size:0.82rem; color:#64748b;">
                        Status: {urlhaus_res.get('url_status')} | Simulated: {urlhaus_res.get('is_simulated', False)}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # Domain Intelligence Details
        st.markdown(
            f"""
            <div class="cyber-panel">
                <div class="cyber-panel-title">🏛️ Domain & DNS Infrastructure Intelligence</div>
                <div style="display:grid; grid-template-columns: 1fr 1fr 1fr; gap:12px; font-size:0.88rem; color:#cbd5e1;">
                    <div><strong>Apex Domain:</strong> <br><span style="color:#38bdf8;">{domain_res.get('domain')}</span></div>
                    <div><strong>Registrar:</strong> <br>{domain_res.get('registrar')}</div>
                    <div><strong>Domain Age:</strong> <br>{domain_res.get('age_days')} days {'⚠️ (NEW)' if domain_res.get('is_newly_registered') else ''}</div>
                    <div><strong>Registration Date:</strong> <br>{domain_res.get('creation_date')}</div>
                    <div><strong>Expiration Date:</strong> <br>{domain_res.get('expiration_date')}</div>
                    <div><strong>Resolved IPs:</strong> <br>{', '.join(domain_res.get('dns_records', [])) if domain_res.get('dns_records') else 'None'}</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # TAB 3: Generative AI Analyst Report
    with t_ai:
        st.markdown("#### 🤖 AI-Powered SOC Incident Triage Report")

        col_gen, col_status = st.columns([1, 3])
        with col_gen:
            if st.button("✨ Generate AI Security Report", type="primary", use_container_width=True):
                with st.spinner("Synthesizing telemetry and generating 8-part incident report..."):
                    report = generate_ai_report(
                        url=raw_url,
                        ml_result=ml_res,
                        shap_result=shap_res,
                        risk_result=risk_res,
                        vt_result=vt_res,
                        urlhaus_result=urlhaus_res,
                        domain_intel=domain_res,
                    )
                    scan["ai_report"] = report

        if scan.get("ai_report"):
            st.markdown(scan["ai_report"])
        else:
            st.info("Click **'Generate AI Security Report'** above to compile a structured 8-part SOC triage report using Generative AI.")

    # TAB 4: SOAR Lite Incident Response
    with t_soar:
        st.markdown("#### ⚡ SOAR Lite Automated Incident Response & Containment")

        playbook = get_playbook_recommendations(risk_res["risk_score"], risk_res["severity"])
        is_blocked, block_info = is_target_blocked(raw_url)

        st.markdown(
            f"""
            <div class="cyber-panel">
                <div class="cyber-panel-title">🛡️ Active Playbook: {playbook['playbook_id']} ({playbook['tier']})</div>
                <ul style="color:#cbd5e1; font-size:0.9rem; line-height:1.6;">
                    {''.join(f"<li>{act}</li>" for act in playbook['recommended_actions'])}
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("##### 🛠️ Analyst Response Actions")
        btn_c1, btn_c2, btn_c3 = st.columns(3)

        with btn_c1:
            if st.button("🚨 Create Incident Ticket", use_container_width=True):
                analyst = st.session_state["user"].get("username", "analyst")
                inc_id = create_incident(
                    url=raw_url,
                    defanged_url=safe_url,
                    severity=risk_res["severity"],
                    title=f"{risk_res['severity']} Threat: {ml_res['prediction']} ({safe_url})",
                    description=f"Risk Score {risk_res['risk_score']}/100. Generated from manual triage.",
                    assigned_analyst=analyst,
                    response_actions="Incident created by analyst",
                )
                st.success(f"Incident Ticket created successfully: `{inc_id}`")

        with btn_c2:
            if is_blocked:
                st.warning("🔒 Already on Simulated Blocklist")
            else:
                if st.button("🚫 Add to Blocklist", use_container_width=True):
                    analyst = st.session_state["user"].get("username", "analyst")
                    ok, b_msg = add_to_blocklist(
                        target=raw_url,
                        reason=f"Manually blocked: {risk_res['severity']} ({risk_res['risk_score']}/100)",
                        risk_score=risk_res["risk_score"],
                        added_by=analyst,
                    )
                    if ok:
                        st.success(b_msg)
                        st.rerun()
                    else:
                        st.error(b_msg)

        with btn_c3:
            # Report Export Buttons
            ai_rep = scan.get("ai_report") or "AI Report not yet compiled."
            md_content = generate_markdown_report(
                raw_url, ml_res, risk_res, ai_rep, vt_res, urlhaus_res, domain_res
            )
            st.download_button(
                "📥 Export Incident Report (MD)",
                data=md_content,
                file_name=f"SOAR_Triage_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown",
                use_container_width=True,
            )
