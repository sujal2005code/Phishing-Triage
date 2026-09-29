"""
Database module for the Phishing Triage system.
Uses SQLite for V1 — stores cases, emails, IOCs, TI results, sandbox results, and reports.
"""

import sqlite3
import json
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("DATABASE_PATH", "data/phishing_triage.db")


def get_connection(db_path: str = None) -> sqlite3.Connection:
    """Get a SQLite connection with row factory enabled."""
    path = db_path or DB_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: str = None):
    """Initialize database tables."""
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'open',
            severity TEXT,
            verdict TEXT,
            risk_score REAL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            sender TEXT,
            recipient TEXT,
            reply_to TEXT,
            subject TEXT,
            date TEXT,
            message_id TEXT,
            return_path TEXT,
            body_text TEXT,
            body_html TEXT,
            raw_headers TEXT,
            auth_results TEXT,
            filename TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        );

        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            ioc_type TEXT NOT NULL,
            value TEXT NOT NULL,
            context TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        );

        CREATE TABLE IF NOT EXISTS threat_intelligence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            ioc_value TEXT NOT NULL,
            ioc_type TEXT,
            result TEXT,
            raw_response TEXT,
            queried_at TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        );

        CREATE TABLE IF NOT EXISTS sandbox_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            target TEXT NOT NULL,
            target_type TEXT,
            verdict TEXT,
            score REAL,
            details TEXT,
            submitted_at TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        );

        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            format TEXT NOT NULL,
            content TEXT NOT NULL,
            filepath TEXT,
            generated_at TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        );

        CREATE TABLE IF NOT EXISTS attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            filename TEXT,
            mime_type TEXT,
            size INTEGER,
            sha256 TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        );
    """)

    conn.commit()
    conn.close()


def create_case(db_path: str = None) -> str:
    """Create a new investigation case. Returns case_id."""
    conn = get_connection(db_path)
    now = datetime.utcnow().isoformat()
    case_id = f"CASE-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{os.urandom(3).hex()}"
    conn.execute(
        "INSERT INTO cases (case_id, status, created_at, updated_at) VALUES (?, ?, ?, ?)",
        (case_id, "open", now, now),
    )
    conn.commit()
    conn.close()
    return case_id


def save_email(case_id: str, email_data: dict, db_path: str = None):
    """Save parsed email data to the database."""
    conn = get_connection(db_path)
    now = datetime.utcnow().isoformat()
    conn.execute(
        """INSERT INTO emails
        (case_id, sender, recipient, reply_to, subject, date, message_id,
         return_path, body_text, body_html, raw_headers, auth_results, filename, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            case_id,
            email_data.get("from"),
            email_data.get("to"),
            email_data.get("reply_to"),
            email_data.get("subject"),
            email_data.get("date"),
            email_data.get("message_id"),
            email_data.get("return_path"),
            email_data.get("body_text"),
            email_data.get("body_html"),
            json.dumps(email_data.get("headers", {})),
            json.dumps(email_data.get("auth_results", {})),
            email_data.get("filename"),
            now,
        ),
    )
    conn.commit()
    conn.close()


def save_iocs(case_id: str, iocs: list, db_path: str = None):
    """Save extracted IOCs."""
    conn = get_connection(db_path)
    now = datetime.utcnow().isoformat()
    for ioc in iocs:
        conn.execute(
            "INSERT INTO iocs (case_id, ioc_type, value, context, created_at) VALUES (?, ?, ?, ?, ?)",
            (case_id, ioc["type"], ioc["value"], ioc.get("context", ""), now),
        )
    conn.commit()
    conn.close()


def save_threat_intel(case_id: str, provider: str, ioc_value: str, ioc_type: str,
                      result: dict, db_path: str = None):
    """Save threat intelligence results."""
    conn = get_connection(db_path)
    now = datetime.utcnow().isoformat()
    conn.execute(
        """INSERT INTO threat_intelligence
        (case_id, provider, ioc_value, ioc_type, result, raw_response, queried_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (case_id, provider, ioc_value, ioc_type,
         json.dumps(result.get("summary", {})),
         json.dumps(result), now),
    )
    conn.commit()
    conn.close()


def save_sandbox_result(case_id: str, result: dict, db_path: str = None):
    """Save sandbox analysis results."""
    conn = get_connection(db_path)
    now = datetime.utcnow().isoformat()
    conn.execute(
        """INSERT INTO sandbox_results
        (case_id, provider, target, target_type, verdict, score, details, submitted_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (case_id, result.get("provider", "unknown"), result.get("target", ""),
         result.get("target_type", ""), result.get("verdict", ""),
         result.get("score"), json.dumps(result.get("details", {})), now),
    )
    conn.commit()
    conn.close()


def save_report(case_id: str, fmt: str, content: str, filepath: str = None,
                db_path: str = None):
    """Save generated report."""
    conn = get_connection(db_path)
    now = datetime.utcnow().isoformat()
    conn.execute(
        "INSERT INTO reports (case_id, format, content, filepath, generated_at) VALUES (?, ?, ?, ?, ?)",
        (case_id, fmt, content, filepath, now),
    )
    conn.commit()
    conn.close()


def update_case_verdict(case_id: str, severity: str, verdict: str,
                        risk_score: float, db_path: str = None):
    """Update case with final risk assessment."""
    conn = get_connection(db_path)
    now = datetime.utcnow().isoformat()
    conn.execute(
        "UPDATE cases SET severity=?, verdict=?, risk_score=?, status='closed', updated_at=? WHERE case_id=?",
        (severity, verdict, risk_score, now, case_id),
    )
    conn.commit()
    conn.close()


def save_attachment(case_id: str, attachment: dict, db_path: str = None):
    """Save attachment metadata."""
    conn = get_connection(db_path)
    now = datetime.utcnow().isoformat()
    conn.execute(
        "INSERT INTO attachments (case_id, filename, mime_type, size, sha256, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (case_id, attachment.get("filename"), attachment.get("mime_type"),
         attachment.get("size"), attachment.get("sha256"), now),
    )
    conn.commit()
    conn.close()


def get_case(case_id: str, db_path: str = None) -> dict:
    """Retrieve a case and all associated data."""
    conn = get_connection(db_path)
    case = conn.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
    if not case:
        conn.close()
        return None

    email = conn.execute("SELECT * FROM emails WHERE case_id=?", (case_id,)).fetchone()
    iocs = conn.execute("SELECT * FROM iocs WHERE case_id=?", (case_id,)).fetchall()
    ti = conn.execute("SELECT * FROM threat_intelligence WHERE case_id=?", (case_id,)).fetchall()
    sandbox = conn.execute("SELECT * FROM sandbox_results WHERE case_id=?", (case_id,)).fetchall()
    reports = conn.execute("SELECT * FROM reports WHERE case_id=?", (case_id,)).fetchall()
    attachments_rows = conn.execute("SELECT * FROM attachments WHERE case_id=?", (case_id,)).fetchall()
    conn.close()

    return {
        "case": dict(case),
        "email": dict(email) if email else None,
        "iocs": [dict(r) for r in iocs],
        "threat_intelligence": [dict(r) for r in ti],
        "sandbox_results": [dict(r) for r in sandbox],
        "reports": [dict(r) for r in reports],
        "attachments": [dict(r) for r in attachments_rows],
    }


def list_cases(db_path: str = None) -> list:
    """List all cases."""
    conn = get_connection(db_path)
    rows = conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")
