"""
Generative AI Security Analyst Module
Generates comprehensive 8-section SOC Incident Reports based on ML predictions,
SHAP explanations, and Threat Intelligence data using Google Gemini API or an
expert deterministic cybersecurity reasoning engine.
"""

import json
import os
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv
import requests

from modules.url_validator import defang_url

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")


def build_analysis_context_prompt(
    url: str,
    ml_result: Dict[str, Any],
    shap_result: Dict[str, Any],
    risk_result: Dict[str, Any],
    vt_result: Dict[str, Any],
    urlhaus_result: Dict[str, Any],
    domain_intel: Dict[str, Any]
) -> str:
    """
    Constructs a factual, structured prompt payload for the AI model.
    """
    safe_url = defang_url(url)
    pred_label = ml_result.get("prediction", "Unknown")
    confidence = ml_result.get("confidence", 0.0) * 100
    risk_score = risk_result.get("risk_score", 0)
    risk_category = risk_result.get("risk_category", "Unknown")

    top_increasing = [item["human_name"] for item in shap_result.get("risk_increasing", [])[:4]]
    top_decreasing = [item["human_name"] for item in shap_result.get("risk_decreasing", [])[:3]]

    vt_status = (
        f"{vt_result.get('malicious_count', 0)} malicious engines, "
        f"{vt_result.get('suspicious_count', 0)} suspicious engines "
        f"(Simulated: {vt_result.get('is_simulated', False)})"
    )

    urlhaus_status = (
        f"Listed: {urlhaus_result.get('is_listed', False)}, "
        f"Threat: {urlhaus_result.get('threat', 'None')} "
        f"(Simulated: {urlhaus_result.get('is_simulated', False)})"
    )

    domain_status = (
        f"Registrar: {domain_intel.get('registrar', 'Unknown')}, "
        f"Age: {domain_intel.get('age_days', 0)} days, "
        f"Newly registered: {domain_intel.get('is_newly_registered', False)}"
    )

    prompt = f"""
You are a Senior SOC Incident Responder and Cybersecurity Analyst. Analyze the following triaged URL investigation data and produce a professional, actionable incident report.

INVESTIGATION CONTEXT:
- Target URL (Defanged): {safe_url}
- Machine Learning Prediction: {pred_label} (Confidence: {confidence:.1f}%)
- Composite Risk Score: {risk_score}/100 ({risk_category})
- Key SHAP Risk Factors (Increasing Threat): {', '.join(top_increasing) if top_increasing else 'None'}
- Key SHAP Mitigating Factors (Decreasing Threat): {', '.join(top_decreasing) if top_decreasing else 'None'}
- VirusTotal Intelligence: {vt_status}
- URLhaus Malware Intelligence: {urlhaus_status}
- Domain Intelligence: {domain_status}

GUIDELINES:
- You MUST generate exactly these 8 numbered sections:
  1. Executive Summary
  2. Threat Explanation
  3. Suspicious Indicators
  4. Potential Attack Type
  5. Risk Assessment
  6. Recommended Security Actions
  7. Incident Response Steps
  8. Prevention Recommendations
- Strictly adhere to supplied facts. Do NOT invent external threat intelligence findings or CVEs that were not provided.
- If VirusTotal or URLhaus is marked as simulated, explicitly state that live external threat feeds were unavailable and fallback intelligence was utilized.
- Present recommendations using concise bullet points and industry-standard SOAR best practices.
"""
    return prompt.strip()


def generate_ai_report(
    url: str,
    ml_result: Dict[str, Any],
    shap_result: Dict[str, Any],
    risk_result: Dict[str, Any],
    vt_result: Dict[str, Any],
    urlhaus_result: Dict[str, Any],
    domain_intel: Dict[str, Any],
    gemini_key: Optional[str] = None
) -> str:
    """
    Generates the AI Incident Report using Gemini API if key is available,
    otherwise uses the built-in deterministic reasoning engine.
    """
    api_key = gemini_key or os.getenv("GEMINI_API_KEY", GEMINI_API_KEY)

    if api_key and api_key != "your_gemini_api_key_here":
        try:
            endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
            prompt_text = build_analysis_context_prompt(
                url, ml_result, shap_result, risk_result, vt_result, urlhaus_result, domain_intel
            )
            payload = {
                "contents": [{"parts": [{"text": prompt_text}]}],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1400},
            }
            resp = requests.post(endpoint, json=payload, timeout=12)
            if resp.status_code == 200:
                data = resp.json()
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                return text
        except Exception:
            pass

    # Expert Deterministic Cybersecurity Reasoning Engine Fallback
    return generate_deterministic_report(url, ml_result, shap_result, risk_result, vt_result, urlhaus_result, domain_intel)


def generate_deterministic_report(
    url: str,
    ml_result: Dict[str, Any],
    shap_result: Dict[str, Any],
    risk_result: Dict[str, Any],
    vt_result: Dict[str, Any],
    urlhaus_result: Dict[str, Any],
    domain_intel: Dict[str, Any]
) -> str:
    """
    Expert rule-driven security analyst reporting engine. Formats the required 8 sections
    strictly conforming to the supplied telemetry.
    """
    safe_url = defang_url(url)
    pred_label = ml_result.get("prediction", "Suspicious")
    confidence = ml_result.get("confidence", 0.85) * 100
    risk_score = risk_result.get("risk_score", 50)
    risk_category = risk_result.get("risk_category", "Suspicious")

    # Threat Intelligence Status Check
    vt_is_sim = vt_result.get("is_simulated", False)
    vt_mal = vt_result.get("malicious_count", 0)
    urlh_is_sim = urlhaus_result.get("is_simulated", False)
    urlh_listed = urlhaus_result.get("is_listed", False)

    sim_note = ""
    if vt_is_sim or urlh_is_sim:
        sim_note = "> **SOC Telemetry Notice:** Live external threat intelligence APIs were unconfigured or unreachable. Findings incorporate internal heuristic telemetry and demonstration threat intelligence feeds.\n\n"

    # Attack classification
    feat = ml_result.get("features", {})
    if feat.get("brand_impersonation") or "phish" in pred_label.lower():
        attack_type = "Credential Harvesting & Brand Impersonation Phishing"
        attack_desc = "The target appears designed to deceive users into submitting sensitive credentials or financial information by spoofing trusted institutional identity."
    elif feat.get("is_ip_address") or urlh_listed or "malicious" in pred_label.lower():
        attack_type = "Malware Distribution & C2 Staging"
        attack_desc = "Indicators suggest this URL is configured as a binary payload delivery point, dropper conduit, or command-and-control beacon host."
    elif pred_label == "Benign":
        attack_type = "No Malicious Vector Detected (Legitimate Resource)"
        attack_desc = "The URL exhibits standard structural hierarchy, authentic certificate/encryption usage, and no known threat feed flags."
    else:
        attack_type = "Unclassified / Potentially Unwanted Redirection"
        attack_desc = "URL features indicate evasive link routing, URL shortener cloaking, or anomalous query parameters."

    # Indicator bullets
    indicators = []
    if feat.get("brand_impersonation"):
        indicators.append("Brand name detected in domain/path outside official registered apex domain.")
    if feat.get("is_ip_address"):
        indicators.append("Direct IP address used instead of canonical domain name.")
    if not feat.get("has_https"):
        indicators.append("Unencrypted HTTP protocol usage (cleartext communication).")
    if feat.get("has_suspicious_keywords"):
        indicators.append("Contains high-risk credential keywords (login, verify, update, account).")
    if feat.get("suspicious_tld"):
        indicators.append("Registered under high-abuse top-level domain (TLD).")
    if feat.get("is_shortened"):
        indicators.append("Cloaked through a known URL shortening proxy service.")
    if feat.get("num_subdomains", 0) >= 2:
        indicators.append(f"Excessive nested subdomain depth ({feat.get('num_subdomains')} levels).")
    if domain_intel.get("is_newly_registered"):
        indicators.append(f"Domain registered recently ({domain_intel.get('age_days')} days ago).")
    if vt_mal > 0:
        indicators.append(f"Flagged by {vt_mal} security vendors on VirusTotal.")
    if urlh_listed:
        indicators.append(f"Confirmed in malware database: {urlhaus_result.get('threat')}.")

    if not indicators:
        indicators.append("No abnormal or hostile lexical indicators observed.")

    ind_formatted = "\n".join(f"- {ind}" for ind in indicators)

    # Recommendations based on risk score
    if risk_score >= 80:
        actions = (
            "- **Immediate Perimeter Blocking:** Add domain and destination IP to enterprise firewall and web proxy blocklists.\n"
            "- **Email Security Gateway:** Quarantine all inbound/outbound emails referencing this link.\n"
            "- **Host Isolation:** If endpoint telemetry shows clicks, isolate affected hosts and initiate memory dump collection.\n"
            "- **Credential Invalidation:** Reset credentials for any users observed navigating to this endpoint."
        )
        response_steps = (
            "1. Triage the incident as **P1 / High Severity** in the SOC queue.\n"
            "2. Query SIEM proxy logs for all internal IP connections to `{safe_url}` within the past 30 days.\n"
            "3. Enforce automated SOAR containment playbook `#SOAR-BLOCK-01`.\n"
            "4. File domain takedown notice with the registrar ({domain_intel.get('registrar', 'Unknown')})."
        )
    elif risk_score >= 40:
        actions = (
            "- **Suspicious Domain Sinkholing:** Flag domain for continuous proxy monitoring.\n"
            "- **Analyst Verification:** Perform sandbox dynamic detonation of the destination in a secure browser.\n"
            "- **User Notification:** Remind end-users not to bypass certificate warnings or enter credentials."
        )
        response_steps = (
            "1. Assign incident ticket for Tier-2 analyst review.\n"
            "2. Verify SSL certificate provenance and domain age.\n"
            "3. Monitor gateway logs for repeated outbound requests."
        )
    else:
        actions = (
            "- **Permit Access:** Allow traffic under default security posture.\n"
            "- **Log Retention:** Record transaction in proxy logs for routine anomaly baseline."
        )
        response_steps = (
            "1. Close triage ticket with status `Resolved - Benign`.\n"
            "2. No active containment required."
        )

    report = f"""{sim_note}### 1. Executive Summary
The security triage engine evaluated `{safe_url}`. The Machine Learning classifier assigned an assessment of **{pred_label}** with **{confidence:.1f}% confidence**. Based on weighted heuristic, model, and threat intelligence components, the composite risk score is **{risk_score}/100 ({risk_category})**.

### 2. Threat Explanation
{shap_result.get('narrative', 'Telemetry analysis indicates specific structural markers aligning with malicious campaigns.')}

### 3. Suspicious Indicators
{ind_formatted}

### 4. Potential Attack Type
**{attack_type}**  
{attack_desc}

### 5. Risk Assessment
- **Severity Rating:** {risk_category} ({risk_score}/100)
- **Model Confidence:** {confidence:.1f}%
- **Domain Reliability:** Registrar `{domain_intel.get('registrar', 'Unknown')}`, Age: `{domain_intel.get('age_days', 'N/A')} days`
- **Threat Vector:** Static lexical evasion and deceptive brand mimicry.

### 6. Recommended Security Actions
{actions}

### 7. Incident Response Steps
{response_steps}

### 8. Prevention Recommendations
- Enforce strict Multi-Factor Authentication (FIDO2 / WebAuthn) resistant to reverse-proxy phishing.
- Implement DNS filtering that blocks newly registered domains (< 30 days) by default.
- Conduct regular simulated phishing awareness campaigns emphasizing URL inspection and domain verification.
"""
    return report.strip()


def chat_with_analyst(user_message: str, context: Optional[Dict[str, Any]] = None) -> str:
    """
    Chatbot assistant for Page 6 (AI Security Analyst). Answers user queries about analyzed
    URLs, incidents, MITRE ATT&CK techniques, and threat hunting strategies.
    """
    api_key = os.getenv("GEMINI_API_KEY", GEMINI_API_KEY)
    ctx_summary = ""
    if context:
        ctx_summary = f"\nACTIVE INCIDENT CONTEXT:\n- Target: {context.get('url')}\n- Prediction: {context.get('prediction')}\n- Risk Score: {context.get('risk_score')}\n- Key Features: {context.get('features')}\n"

    system_instruction = (
        "You are an expert SOC Analyst and cybersecurity assistant in the SOAR Lite platform. "
        "Answer technical security questions concisely and professionally. "
        "Reference MITRE ATT&CK techniques, IOC validation, or incident remediation steps where appropriate. "
        "Do not invent facts or external scan results not in context."
    )

    if api_key and api_key != "your_gemini_api_key_here":
        try:
            endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
            full_prompt = f"{system_instruction}\n{ctx_summary}\nUser Question: {user_message}"
            payload = {
                "contents": [{"parts": [{"text": full_prompt}]}],
                "generationConfig": {"temperature": 0.3, "maxOutputTokens": 800},
            }
            resp = requests.post(endpoint, json=payload, timeout=10)
            if resp.status_code == 200:
                return resp.json()["candidates"][0]["content"]["parts"][0]["text"]
        except Exception:
            pass

    # Built-in Analyst Intelligence Fallback
    user_lower = user_message.lower()
    if "mitre" in user_lower or "attack" in user_lower:
        return (
            "**MITRE ATT&CK Mapping:**\n\n"
            "- **T1566.002 (Phishing: Spearphishing Link):** Adversaries send malicious links to lure victims into visiting malicious websites.\n"
            "- **T1608.001 (Stage Capabilities: Upload Malware):** Malicious URLs serving direct binaries or staging droppers.\n"
            "- **T1584.001 (Compromise Infrastructure: Domains):** Adversaries register deceptive domains resembling trusted brands."
        )
    elif "block" in user_lower or "firewall" in user_lower:
        return (
            "**Blocking Recommendation:**\n\n"
            "1. For URLs with Risk Score > 80, immediately add the Fully Qualified Domain Name (FQDN) to your Egress Proxy and DNS RPZ (Response Policy Zone).\n"
            "2. If an IP literal is observed, configure an egress firewall drop rule for the /32 address on ports 80 and 443.\n"
            "3. Use the 'Add to Blocklist' action button in SOAR Lite to simulate local quarantine."
        )
    elif "how" in user_lower and "score" in user_lower:
        return (
            "**Risk Scoring Methodology:**\n\n"
            "The 0-100 composite score integrates:\n"
            "- **ML Classifier (40%):** Trained model evaluating 20 lexical & structural features.\n"
            "- **Heuristic Engine (25%):** Specific red flags (brand impersonation, IP hosts, suspicious TLDs, missing HTTPS).\n"
            "- **Threat Intelligence (25%):** VirusTotal vendor consensus and URLhaus malware records.\n"
            "- **Domain Age (10%):** Newly registered domains (< 30 days) receive elevated risk weight."
        )
    else:
        return (
            f"**SOC Assistant:** I received your query regarding '{user_message}'. "
            "Based on our active triage telemetry, URLs with high entropy, non-standard TLDs, and missing HTTPS "
            "correlate strongly with credential harvesting campaigns. For detailed analysis, refer to the SHAP explanation "
            "and generated incident report."
        )
