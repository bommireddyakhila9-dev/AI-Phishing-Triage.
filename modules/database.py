"""
SQLite Database Layer for SOAR Lite
Provides schema initialization, secure parameterized CRUD operations for
users, URL analyses, incidents, and blocklist entries.
"""

import os
import sqlite3
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from dotenv import load_dotenv

load_dotenv()

DEFAULT_DB_PATH = os.getenv("DATABASE_PATH", os.path.join("data", "soar_lite.db"))


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Returns a connection to the SQLite database with row factory enabled.
    """
    path = db_path or DEFAULT_DB_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """
    Initializes tables and indexes for users, URL analyses, incidents, and blocklist.
    """
    conn = get_db_connection(db_path)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'Security Analyst',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS url_analyses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        defanged_url TEXT NOT NULL,
        prediction TEXT NOT NULL,
        confidence REAL NOT NULL,
        risk_score INTEGER NOT NULL,
        risk_category TEXT NOT NULL,
        threat_intel_summary TEXT,
        analysis_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        analyzed_by TEXT DEFAULT 'analyst'
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT UNIQUE NOT NULL,
        url TEXT NOT NULL,
        defanged_url TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'New',
        title TEXT NOT NULL,
        description TEXT,
        assigned_analyst TEXT DEFAULT 'Unassigned',
        response_actions TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS blocklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT UNIQUE NOT NULL,
        target_type TEXT DEFAULT 'URL',
        reason TEXT NOT NULL,
        risk_score INTEGER DEFAULT 0,
        added_by TEXT DEFAULT 'analyst',
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Indices for performance
    cur.execute("CREATE INDEX IF NOT EXISTS idx_analyses_ts ON url_analyses(analysis_timestamp);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_sev ON incidents(severity);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_stat ON incidents(status);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_blocklist_tgt ON blocklist(target);")

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# URL Analyses Operations
# ---------------------------------------------------------------------------

def save_analysis(
    url: str,
    defanged_url: str,
    prediction: str,
    confidence: float,
    risk_score: int,
    risk_category: str,
    threat_intel_summary: str = "",
    analyzed_by: str = "analyst",
    db_path: Optional[str] = None
) -> int:
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO url_analyses 
        (url, defanged_url, prediction, confidence, risk_score, risk_category, threat_intel_summary, analyzed_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (url, defanged_url, prediction, float(confidence), int(risk_score), risk_category, threat_intel_summary, analyzed_by))
    conn.commit()
    inserted_id = cur.lastrowid
    conn.close()
    return inserted_id


def get_recent_analyses(limit: int = 50, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        SELECT id, url, defanged_url, prediction, confidence, risk_score, risk_category, 
               threat_intel_summary, analysis_timestamp, analyzed_by
        FROM url_analyses
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_metrics_summary(db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Returns aggregated security dashboard KPIs.
    """
    conn = get_db_connection(db_path)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM url_analyses;")
    total_analyzed = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM url_analyses WHERE LOWER(prediction) = 'malicious';")
    malicious_count = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM url_analyses WHERE LOWER(prediction) = 'phishing';")
    phishing_count = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM url_analyses WHERE LOWER(prediction) = 'suspicious';")
    suspicious_count = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM incidents WHERE LOWER(severity) IN ('critical', 'high');")
    critical_incidents = cur.fetchone()[0]

    detection_rate = 0.0
    if total_analyzed > 0:
        threats = malicious_count + phishing_count + suspicious_count
        detection_rate = round((threats / total_analyzed) * 100, 1)

    # Classification distribution
    cur.execute("SELECT prediction, COUNT(*) as count FROM url_analyses GROUP BY prediction;")
    pred_dist = {row["prediction"]: row["count"] for row in cur.fetchall()}

    # Severity distribution
    cur.execute("SELECT risk_category, COUNT(*) as count FROM url_analyses GROUP BY risk_category;")
    sev_dist = {row["risk_category"]: row["count"] for row in cur.fetchall()}

    conn.close()
    return {
        "total_analyzed": total_analyzed,
        "malicious_count": malicious_count,
        "phishing_count": phishing_count,
        "suspicious_count": suspicious_count,
        "critical_incidents": critical_incidents,
        "detection_rate": detection_rate,
        "prediction_distribution": pred_dist,
        "severity_distribution": sev_dist,
    }


# ---------------------------------------------------------------------------
# Incidents Operations
# ---------------------------------------------------------------------------

def create_incident(
    url: str,
    defanged_url: str,
    severity: str,
    title: str,
    description: str,
    assigned_analyst: str = "analyst",
    response_actions: str = "Investigation initiated",
    db_path: Optional[str] = None
) -> str:
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    inc_id = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    cur.execute("""
        INSERT INTO incidents 
        (incident_id, url, defanged_url, severity, status, title, description, assigned_analyst, response_actions)
        VALUES (?, ?, ?, ?, 'New', ?, ?, ?, ?)
    """, (inc_id, url, defanged_url, severity, title, description, assigned_analyst, response_actions))
    conn.commit()
    conn.close()
    return inc_id


def update_incident_status(
    incident_id: str,
    status: str,
    assigned_analyst: Optional[str] = None,
    response_actions: Optional[str] = None,
    db_path: Optional[str] = None
) -> bool:
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    now_ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    updates = ["status = ?", "updated_at = ?"]
    params: List[Any] = [status, now_ts]

    if assigned_analyst is not None:
        updates.append("assigned_analyst = ?")
        params.append(assigned_analyst)
    if response_actions is not None:
        updates.append("response_actions = ?")
        params.append(response_actions)

    params.append(incident_id)
    query = f"UPDATE incidents SET {', '.join(updates)} WHERE incident_id = ?"
    cur.execute(query, tuple(params))
    conn.commit()
    affected = cur.rowcount > 0
    conn.close()
    return affected


def get_incidents(
    status_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    search_query: Optional[str] = None,
    db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    cur = conn.cursor()

    query = "SELECT * FROM incidents WHERE 1=1"
    params: List[Any] = []

    if status_filter and status_filter != "All":
        query += " AND status = ?"
        params.append(status_filter)

    if severity_filter and severity_filter != "All":
        query += " AND severity = ?"
        params.append(severity_filter)

    if search_query:
        query += " AND (url LIKE ? OR title LIKE ? OR incident_id LIKE ?)"
        wildcard = f"%{search_query}%"
        params.extend([wildcard, wildcard, wildcard])

    query += " ORDER BY id DESC"
    cur.execute(query, tuple(params))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Blocklist Operations
# ---------------------------------------------------------------------------

def add_to_blocklist(
    target: str,
    reason: str,
    risk_score: int = 100,
    target_type: str = "URL",
    added_by: str = "analyst",
    db_path: Optional[str] = None
) -> Tuple[bool, str]:
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO blocklist (target, target_type, reason, risk_score, added_by)
            VALUES (?, ?, ?, ?, ?)
        """, (target.strip(), target_type, reason, int(risk_score), added_by))
        conn.commit()
        conn.close()
        return True, f"'{target}' successfully added to simulated blocklist."
    except sqlite3.IntegrityError:
        conn.close()
        return False, f"Target '{target}' is already on the blocklist."


def is_target_blocked(target: str, db_path: Optional[str] = None) -> Tuple[bool, Optional[Dict[str, Any]]]:
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM blocklist WHERE target = ? LIMIT 1", (target.strip(),))
    row = cur.fetchone()
    conn.close()
    if row:
        return True, dict(row)
    return False, None


def get_all_blocklist(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM blocklist ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def remove_from_blocklist(entry_id: int, db_path: Optional[str] = None) -> bool:
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM blocklist WHERE id = ?", (entry_id,))
    conn.commit()
    affected = cur.rowcount > 0
    conn.close()
    return affected
