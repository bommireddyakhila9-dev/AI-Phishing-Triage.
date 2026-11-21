"""
AI Security Analyst Chatbot Module (Page 6)
Interactive conversational SOC assistant for querying threat indicators,
MITRE ATT&CK mappings, incident investigation tactics, and SOAR automation.
"""

import streamlit as st

from modules.ai_analyst import chat_with_analyst
from modules.database import get_recent_analyses
from modules.ui_common import load_custom_css, render_header, require_auth

load_custom_css()
require_auth()

render_header("AI Cybersecurity Analyst Assistant", "Interactive conversational assistant grounded in your triaged telemetry and incidents.")

# Session chat history initialization
if "chat_messages" not in st.session_state:
    st.session_state["chat_messages"] = [
        {
            "role": "assistant",
            "content": (
                "👋 Hello Analyst! I am your AI SOC Assistant. "
                "You can query me regarding triaged URLs, MITRE ATT&CK techniques, "
                "perimeter blocking policies, or request assistance drafting executive incident summaries."
            ),
        }
    ]

# Optional Incident / URL Context Binding
recent_scans = get_recent_analyses(limit=10)
scan_options = {"-- General Cyber Q&A (No specific URL) --": None}
for s in recent_scans:
    key_name = f"[{s['prediction']}] {s['defanged_url'][:40]} (Score {s['risk_score']})"
    scan_options[key_name] = s

selected_ctx_name = st.selectbox("Ground Chat in Specific Triaged URL Context:", list(scan_options.keys()))
active_context = scan_options[selected_ctx_name]

if active_context:
    st.info(
        f"🎯 **Active Telemetry Context:** `{active_context['defanged_url']}` | "
        f"**Prediction:** `{active_context['prediction']}` | "
        f"**Risk Score:** `{active_context['risk_score']}/100`"
    )

st.markdown("---")

# Quick Prompt Suggestions
st.markdown("##### 💡 Suggested Analyst Inquiries")
q_c1, q_c2, q_c3 = st.columns(3)
quick_prompt = None

with q_c1:
    if st.button("🛡️ What MITRE ATT&CK techniques apply?", use_container_width=True):
        quick_prompt = "What MITRE ATT&CK techniques apply to this threat profile?"
with q_c2:
    if st.button("🚫 Recommend firewall & proxy blocking rules", use_container_width=True):
        quick_prompt = "Recommend firewall and egress proxy blocking rules for this target."
with q_c3:
    if st.button("📊 Explain the risk scoring methodology", use_container_width=True):
        quick_prompt = "How was the composite risk score calculated?"

# Display Conversation History
for msg in st.session_state["chat_messages"]:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# Handle Chat Input
user_input = st.chat_input("Ask the AI Security Analyst a question...")

prompt_to_send = quick_prompt or user_input

if prompt_to_send:
    # Append User Message
    st.session_state["chat_messages"].append({"role": "user", "content": prompt_to_send})
    with st.chat_message("user"):
        st.markdown(prompt_to_send)

    # Generate Assistant Response
    with st.chat_message("assistant"):
        with st.spinner("AI Analyst analyzing question and context..."):
            ctx_payload = None
            if active_context:
                ctx_payload = {
                    "url": active_context["defanged_url"],
                    "prediction": active_context["prediction"],
                    "risk_score": active_context["risk_score"],
                    "features": active_context.get("threat_intel_summary", ""),
                }
            reply = chat_with_analyst(prompt_to_send, context=ctx_payload)
            st.markdown(reply)
            st.session_state["chat_messages"].append({"role": "assistant", "content": reply})
