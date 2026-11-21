"""
Tests for SQLite database operations: analyses, incidents, and blocklist.
"""

import os
import tempfile
import pytest
from modules.database import (
    add_to_blocklist,
    create_incident,
    get_all_blocklist,
    get_incidents,
    get_metrics_summary,
    get_recent_analyses,
    init_db,
    is_target_blocked,
    remove_from_blocklist,
    save_analysis,
    update_incident_status,
)


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    yield path
    if os.path.exists(path):
        os.remove(path)


def test_save_and_retrieve_analysis(temp_db):
    row_id = save_analysis(
        url="http://test-malicious.com",
        defanged_url="hxxp://test-malicious[.]com",
        prediction="Malicious",
        confidence=0.96,
        risk_score=85,
        risk_category="High Risk",
        threat_intel_summary="VT flagged",
        db_path=temp_db,
    )
    assert row_id > 0

    recent = get_recent_analyses(limit=5, db_path=temp_db)
    assert len(recent) == 1
    assert recent[0]["prediction"] == "Malicious"
    assert recent[0]["risk_score"] == 85


def test_incident_lifecycle(temp_db):
    inc_id = create_incident(
        url="http://phish-test.com",
        defanged_url="hxxp://phish-test[.]com",
        severity="Critical",
        title="Critical Phishing Attack",
        description="Test incident",
        db_path=temp_db,
    )
    assert inc_id.startswith("INC-")

    incidents = get_incidents(db_path=temp_db)
    assert len(incidents) == 1
    assert incidents[0]["status"] == "New"

    updated = update_incident_status(
        incident_id=inc_id,
        status="Resolved",
        response_actions="Quarantine enforced",
        db_path=temp_db,
    )
    assert updated is True

    incidents_after = get_incidents(db_path=temp_db)
    assert incidents_after[0]["status"] == "Resolved"


def test_blocklist_operations(temp_db):
    ok, msg = add_to_blocklist(
        target="evil-domain.top",
        reason="Malware C2",
        risk_score=95,
        db_path=temp_db,
    )
    assert ok is True

    # Duplicate block should be rejected
    ok2, msg2 = add_to_blocklist(
        target="evil-domain.top",
        reason="Duplicate",
        db_path=temp_db,
    )
    assert ok2 is False

    is_blocked, entry = is_target_blocked("evil-domain.top", db_path=temp_db)
    assert is_blocked is True
    assert entry["risk_score"] == 95

    # Remove
    removed = remove_from_blocklist(entry["id"], db_path=temp_db)
    assert removed is True

    is_blocked_after, _ = is_target_blocked("evil-domain.top", db_path=temp_db)
    assert is_blocked_after is False
