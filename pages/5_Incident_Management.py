"""
SOAR Lite Incident Management Portal (Page 5)
Enables searching, filtering, triaging, updating statuses, assigning analysts,
and exporting formal incident reports.
"""

from datetime import datetime
import pandas as pd
import streamlit as st

from modules.database import create_incident, get_incidents, update_incident_status
from modules.ui_common import load_custom_css, render_header, render_metric_card, require_auth
from modules.url_validator import defang_url

load_custom_css()
require_auth()

render_header("SOAR Incident Management Center", "Track, investigate, assign, and remediate cybersecurity incident tickets.")

# Filter Controls Bar
st.markdown("##### 🔍 Incident Search & Triage Filters")
col_s1, col_s2, col_s3, col_s4 = st.columns([2, 1, 1, 1])

with col_s1:
    search_query = st.text_input("Search Incidents (by ID, Title, or URL):", placeholder="e.g. INC-2026 or paypal")

with col_s2:
    sev_filter = st.selectbox("Filter Severity:", ["All", "Critical", "High", "Moderate", "Low"])

with col_s3:
    status_filter = st.selectbox("Filter Status:", ["All", "New", "Under Investigation", "Resolved", "Closed"])

with col_s4:
    if st.button("➕ Seed Demo Incidents", help="Populates sample incidents if database is empty"):
        create_incident(
            url="http://paypal-security-verification-login.com.account-update.xyz/signin",
            defanged_url="hxxp://paypal-security-verification-login[.]com.account-update.xyz/signin",
            severity="Critical",
            title="Critical Phishing: PayPal Credential Harvester",
            description="High-fidelity brand impersonation targeting consumer banking credentials.",
            assigned_analyst="analyst",
            response_actions="Simulated blocklist enforced; escalation P1 triggered.",
        )
        create_incident(
            url="http://192.168.1.105:8080/payload.exe",
            defanged_url="hxxp://192.168.1.105:8080/payload[.]exe",
            severity="High",
            title="High Threat: Direct IP Binary Dropper",
            description="Malicious executable distribution from raw numerical host.",
            assigned_analyst="analyst",
            response_actions="Perimeter firewall block recommended.",
        )
        st.success("Seeded sample incidents!")
        st.rerun()

incidents = get_incidents(
    status_filter=status_filter if status_filter != "All" else None,
    severity_filter=sev_filter if sev_filter != "All" else None,
    search_query=search_query.strip() if search_query else None,
)

# Incident Metrics
all_incidents = get_incidents()
total_inc = len(all_incidents)
open_inc = len([i for i in all_incidents if i["status"] in ("New", "Under Investigation")])
crit_inc = len([i for i in all_incidents if i["severity"] in ("Critical", "High")])
resolved_inc = len([i for i in all_incidents if i["status"] in ("Resolved", "Closed")])

m1, m2, m3, m4 = st.columns(4)
with m1:
    render_metric_card("Total Incidents", str(total_inc), "All Records", "badge-low")
with m2:
    render_metric_card("Active Open", str(open_inc), "Action Required", "badge-high" if open_inc > 0 else "badge-low")
with m3:
    render_metric_card("Critical / High", str(crit_inc), "Severe Risk", "badge-critical" if crit_inc > 0 else "badge-low")
with m4:
    render_metric_card("Resolved", str(resolved_inc), "Remediated", "badge-low")

st.markdown("<br>", unsafe_allow_html=True)

if not incidents:
    st.info("No security incidents match the selected filter criteria. Create incidents via the URL Scanner or click 'Seed Demo Incidents' above.")
else:
    st.markdown(f"### 📋 Active Incident Tickets ({len(incidents)})")

    for inc in incidents:
        inc_id = inc["incident_id"]
        sev = inc["severity"]
        status = inc["status"]

        # Color coding
        if sev == "Critical":
            b_class = "badge-critical"
        elif sev == "High":
            b_class = "badge-high"
        elif sev == "Moderate":
            b_class = "badge-moderate"
        else:
            b_class = "badge-low"

        with st.expander(f"🚨 **{inc_id}** | {inc['title']} [{status}]", expanded=(status == "New")):
            col_d1, col_d2 = st.columns([2, 1])

            with col_d1:
                st.markdown(f"**Target URL (Defanged):** `{inc['defanged_url']}`")
                st.markdown(f"**Severity:** <span class='soc-metric-badge {b_class}'>{sev}</span>", unsafe_allow_html=True)
                st.markdown(f"**Description:** {inc['description']}")
                st.markdown(f"**Response Actions Logged:** `{inc.get('response_actions') or 'None'}`")
                st.markdown(f"**Created:** `{inc['created_at']}` | **Updated:** `{inc['updated_at']}`")

            with col_d2:
                st.markdown("##### ⚙️ Update Ticket")
                new_status = st.selectbox(
                    "Status:",
                    ["New", "Under Investigation", "Resolved", "Closed"],
                    index=["New", "Under Investigation", "Resolved", "Closed"].index(status),
                    key=f"status_{inc_id}",
                )

                new_analyst = st.text_input(
                    "Assignee:",
                    value=inc.get("assigned_analyst", "analyst"),
                    key=f"analyst_{inc_id}",
                )

                new_action = st.text_input(
                    "Log Action Note:",
                    placeholder="e.g. Host quarantined",
                    key=f"action_{inc_id}",
                )

                if st.button("Save Updates", key=f"btn_save_{inc_id}"):
                    act_log = inc.get("response_actions") or ""
                    if new_action.strip():
                        act_log = f"{act_log}; {new_action.strip()}" if act_log else new_action.strip()
                    update_incident_status(
                        incident_id=inc_id,
                        status=new_status,
                        assigned_analyst=new_analyst,
                        response_actions=act_log,
                    )
                    st.success("Incident updated!")
                    st.rerun()

            # Export individual incident report
            inc_report_md = f"""# Incident Report: {inc_id}
- **Title:** {inc['title']}
- **Severity:** {sev}
- **Status:** {status}
- **Target URL:** {inc['defanged_url']}
- **Assigned Analyst:** {inc.get('assigned_analyst')}
- **Description:** {inc['description']}
- **Actions:** {inc.get('response_actions')}
- **Created:** {inc['created_at']}
"""
            st.download_button(
                "📥 Export Incident Ticket (MD)",
                data=inc_report_md,
                file_name=f"Incident_{inc_id}.md",
                mime="text/markdown",
                key=f"dl_{inc_id}",
            )
