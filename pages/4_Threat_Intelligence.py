"""
Threat Intelligence Explorer (Page 4)
Direct investigation portal querying VirusTotal, abuse.ch URLhaus, and Domain WHOIS/RDAP.
"""

import os
import streamlit as st

from modules.domain_intelligence import query_domain_intelligence
from modules.ui_common import load_custom_css, render_header, render_metric_card, require_auth
from modules.url_validator import defang_url, is_valid_url
from modules.urlhaus import query_urlhaus
from modules.virustotal import query_virustotal

load_custom_css()
require_auth()

render_header("Threat Intelligence Aggregator", "Query multi-vendor threat reputation feeds, malware databases, and domain registries.")

# API Connection Status Check
vt_key_set = bool(os.getenv("VIRUSTOTAL_API_KEY") and os.getenv("VIRUSTOTAL_API_KEY") != "your_virustotal_api_key_here")
urlh_key_set = bool(os.getenv("URLHAUS_API_KEY") and os.getenv("URLHAUS_API_KEY") != "your_urlhaus_api_key_here")

c_stat1, c_stat2 = st.columns(2)
with c_stat1:
    if vt_key_set:
        st.success("🟢 VirusTotal API: Connected")
    else:
        st.info("ℹ️ VirusTotal API: Running in Deterministic Demo Mode (Set VIRUSTOTAL_API_KEY in .env)")
with c_stat2:
    if urlh_key_set:
        st.success("🟢 URLhaus API: Connected")
    else:
        st.info("ℹ️ URLhaus API: Connected (Public Feed / Demo Mode)")

st.markdown("---")

# Target Query Form
st.markdown("#### 🔎 Query URL / Domain Intelligence")
query_col, sample_col = st.columns([3, 1])

with sample_col:
    ti_sample = st.selectbox(
        "Load Sample Target:",
        [
            "-- Custom --",
            "http://evil-c2-server-panel.xyz/beacon.php?cmd=exec",
            "http://paypal-security-verification-login.com.account-update.xyz/signin",
            "https://www.google.com",
            "http://192.168.1.105:8080/payload.exe",
        ]
    )

default_ti_input = ti_sample if ti_sample != "-- Custom --" else "http://evil-c2-server-panel.xyz/beacon.php?cmd=exec"
target_input = st.text_input("Enter Target URL to Query:", value=default_ti_input)

if st.button("Query Threat Feeds", type="primary"):
    if target_input.strip():
        valid, val_msg = is_valid_url(target_input.strip())
        if not valid:
            st.error(f"Invalid URL: {val_msg}")
            st.stop()

        raw_url = target_input.strip()
        safe_url = defang_url(raw_url)

        with st.spinner("Aggregating threat intelligence from VirusTotal, URLhaus, and RDAP..."):
            vt = query_virustotal(raw_url)
            urlh = query_urlhaus(raw_url)
            dom = query_domain_intelligence(raw_url)

        st.markdown("---")
        st.markdown(f"### 🛡️ Intelligence Dossier for `{safe_url}`")

        # Top Threat Intel Metrics
        tm1, tm2, tm3, tm4 = st.columns(4)
        with tm1:
            render_metric_card(
                "VT Malicious",
                str(vt.get("malicious_count", 0)),
                f"of {vt.get('total_engines', 0)} engines",
                "badge-critical" if vt.get("malicious_count", 0) > 0 else "badge-low"
            )
        with tm2:
            render_metric_card(
                "URLhaus Status",
                "LISTED" if urlh.get("is_listed") else "CLEAN",
                urlh.get("threat", "None"),
                "badge-critical" if urlh.get("is_listed") else "badge-low"
            )
        with tm3:
            render_metric_card(
                "Domain Age",
                f"{dom.get('age_days', 0)} Days",
                "NEW DOMAIN" if dom.get("is_newly_registered") else "Established",
                "badge-high" if dom.get("is_newly_registered") else "badge-low"
            )
        with tm4:
            render_metric_card(
                "Registrar",
                dom.get("registrar", "Unknown")[:18],
                "ICANN RDAP",
                "badge-moderate"
            )

        st.markdown("<br>", unsafe_allow_html=True)

        # Detailed breakdown tabs
        tab_vt, tab_urlh, tab_dom = st.tabs(["VirusTotal Analysis", "URLhaus Findings", "Domain & DNS Records"])

        with tab_vt:
            st.markdown("##### VirusTotal Engine Breakdown")
            st.write(vt.get("status_message"))
            if vt.get("flagging_vendors"):
                st.markdown("###### Flagging Security Vendors:")
                st.dataframe(vt["flagging_vendors"], use_container_width=True)
            else:
                st.info("No security engines flagged this URL as malicious.")

            if vt.get("is_simulated"):
                st.caption(f"Note: {vt.get('simulation_notice')}")

        with tab_urlh:
            st.markdown("##### abuse.ch URLhaus Details")
            st.write(f"- **Listing Status:** {'Actively Flagged' if urlh.get('is_listed') else 'Not Found'}")
            st.write(f"- **Identified Threat:** {urlh.get('threat')}")
            st.write(f"- **Payload Tags:** {', '.join(urlh.get('tags', [])) if urlh.get('tags') else 'None'}")
            st.write(f"- **Reporter:** {urlh.get('reporter')}")
            st.write(f"- **Date Added:** {urlh.get('date_added')}")

            if urlh.get("is_simulated"):
                st.caption(f"Note: {urlh.get('simulation_notice')}")

        with tab_dom:
            st.markdown("##### WHOIS / RDAP Registration Metadata")
            st.write(f"- **Domain Name:** `{dom.get('domain')}`")
            st.write(f"- **Registrar:** {dom.get('registrar')}")
            st.write(f"- **Creation Date:** {dom.get('creation_date')}")
            st.write(f"- **Expiration Date:** {dom.get('expiration_date')}")
            st.write(f"- **Calculated Domain Age:** {dom.get('age_days')} days")
            st.write(f"- **Newly Registered Flag (<60 days):** {dom.get('is_newly_registered')}")
            st.markdown("###### Resolved DNS IPv4 Addresses:")
            if dom.get("dns_records"):
                for ip in dom["dns_records"]:
                    st.code(ip, language="text")
            else:
                st.info("No A-records resolved for this hostname.")
