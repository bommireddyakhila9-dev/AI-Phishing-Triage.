"""
SOAR Lite Incident Response & Playbook Automation Module
Orchestrates automated playbook recommendations, incident ticket generation,
and local simulated perimeter blocklisting based on risk severity tiers.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from modules.database import add_to_blocklist, create_incident, is_target_blocked, update_incident_status
from modules.url_validator import defang_url


def get_playbook_recommendations(risk_score: int, severity: str) -> Dict[str, Any]:
    """
    Returns recommended SOAR playbooks and actions mapped to severity tiers.
    """
    if risk_score <= 20:
        return {
            "tier": "Low Risk",
            "playbook_id": "PLAYBOOK-LOW-01",
            "recommended_actions": [
                "Record telemetry in local analysis database.",
                "Maintain standard endpoint monitoring (no containment required).",
                "Log HTTP transaction for periodic SIEM baseline."
            ],
            "auto_actions": ["Log Transaction"],
            "requires_escalation": False,
        }
    elif risk_score <= 40:
        return {
            "tier": "Moderate Risk",
            "playbook_id": "PLAYBOOK-MOD-02",
            "recommended_actions": [
                "Investigate suspicious lexical indicators and domain age.",
                "Verify domain ownership and registrar credentials.",
                "Review multi-vendor reputation telemetry across threat feeds.",
                "Schedule re-scan in 24 hours to monitor reputation degradation."
            ],
            "auto_actions": ["Flag for Analyst Triage"],
            "requires_escalation": False,
        }
    elif risk_score <= 80:
        return {
            "tier": "High Risk",
            "playbook_id": "PLAYBOOK-HIGH-03",
            "recommended_actions": [
                "Execute local simulated blocklist quarantine.",
                "Alert Tier-2 Security Operations Center (SOC) team.",
                "Create high-priority incident ticket for investigation.",
                "Search enterprise proxy logs for previous user visits."
            ],
            "auto_actions": ["Simulated Blocklist", "Generate Incident Ticket"],
            "requires_escalation": True,
        }
    else:
        return {
            "tier": "Critical Risk",
            "playbook_id": "PLAYBOOK-CRIT-04",
            "recommended_actions": [
                "Automatically quarantine URL in local simulated blocklist.",
                "Generate comprehensive AI incident report.",
                "Recommend domain/IP egress blocking at enterprise firewall/proxy.",
                "Immediately escalate to senior SOC on-call incident commander.",
                "Trigger automated credential reset review for exposed accounts."
            ],
            "auto_actions": ["Enforce Blocklist Quarantine", "Auto-Create High Incident", "Trigger Notification"],
            "requires_escalation": True,
        }


def execute_soar_containment(
    url: str,
    risk_score: int,
    severity: str,
    prediction: str,
    analyst_name: str = "analyst"
) -> Dict[str, Any]:
    """
    Executes automated SOAR containment:
    - If Critical, automatically adds URL to the local simulated blocklist and creates an incident.
    """
    safe_url = defang_url(url)
    actions_taken = []
    incident_id = None
    blocked = False

    # Check if already blocked
    is_blocked, _ = is_target_blocked(url)

    if risk_score >= 80 and not is_blocked:
        success, msg = add_to_blocklist(
            target=url,
            reason=f"Automated SOAR quarantine: {severity} ({risk_score}/100) - {prediction}",
            risk_score=risk_score,
            target_type="URL",
            added_by=analyst_name
        )
        if success:
            actions_taken.append(f"Added to simulated blocklist: {msg}")
            blocked = True

    # Auto-create incident for High and Critical threats
    if risk_score >= 60:
        title = f"{severity} Threat Detected: {prediction} ({safe_url})"
        desc = (
            f"Automated SOAR incident generated during URL triage. "
            f"Risk score evaluated at {risk_score}/100 with prediction {prediction}. "
            f"Simulated blocklist status: {'Active' if blocked or is_blocked else 'Pending'}"
        )
        incident_id = create_incident(
            url=url,
            defanged_url=safe_url,
            severity=severity,
            title=title,
            description=desc,
            assigned_analyst=analyst_name,
            response_actions="; ".join(actions_taken) if actions_taken else "Triage completed"
        )
        actions_taken.append(f"Created Incident Ticket: {incident_id}")

    return {
        "incident_id": incident_id,
        "is_blocked": blocked or is_blocked,
        "actions_taken": actions_taken,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
