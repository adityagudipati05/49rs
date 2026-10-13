"""
db.py - SQLite initialization and helpers for approvals and audit_log.

Schema:
  approvals(action_id PK, decision, analyst, timestamp, evidence_ids, comment)
  audit_log(id INTEGER PK AUTOINCREMENT, timestamp, analyst, event, action_id, details)

The audit log is append-only and written only by real events.
"""
import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "soc_copilot.db")


def _resolve_path(db_path: Optional[str]) -> str:
    """Resolve DB path, reading DB_PATH dynamically so tests can monkeypatch it."""
    return db_path if db_path is not None else DB_PATH


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    path = _resolve_path(db_path)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Create tables if they don't exist. Idempotent."""
    conn = get_connection(db_path)
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS approvals (
                action_id   TEXT PRIMARY KEY,
                decision    TEXT NOT NULL CHECK(decision IN ('approved', 'rejected')),
                analyst     TEXT NOT NULL,
                timestamp   TEXT NOT NULL,
                evidence_ids TEXT,
                comment     TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                analyst     TEXT NOT NULL,
                event       TEXT NOT NULL,
                action_id   TEXT,
                details     TEXT
            );
        """)
        conn.commit()
    finally:
        conn.close()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Approvals helpers
# ---------------------------------------------------------------------------

def get_approval(action_id: str, db_path: Optional[str] = None) -> Optional[dict]:
    """Return the approval row for action_id, or None."""
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM approvals WHERE action_id = ?", (action_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def upsert_approval(
    action_id: str,
    decision: str,
    analyst: str,
    comment: Optional[str],
    evidence_ids: Optional[list],
    db_path: Optional[str] = None,
) -> None:
    """Insert or replace an approval record."""
    conn = get_connection(db_path)
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO approvals
                (action_id, decision, analyst, timestamp, evidence_ids, comment)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                action_id,
                decision,
                analyst,
                _now_iso(),
                json.dumps(evidence_ids) if evidence_ids else None,
                comment,
            ),
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Audit log helpers
# ---------------------------------------------------------------------------

def append_audit(
    analyst: str,
    event: str,
    action_id: Optional[str],
    details: Optional[dict],
    db_path: Optional[str] = None,
) -> None:
    """Append an entry to the audit log. This is the only write path."""
    conn = get_connection(db_path)
    try:
        conn.execute(
            """
            INSERT INTO audit_log (timestamp, analyst, event, action_id, details)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                _now_iso(),
                analyst,
                event,
                action_id,
                json.dumps(details) if details else None,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_audit_log(db_path: Optional[str] = None, limit: int = 500) -> list[dict]:
    """Return audit log entries newest first."""
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Enforcement helper (shared — not duplicated in UI)
# ---------------------------------------------------------------------------

def require_approved(action_id: str, db_path: Optional[str] = None) -> tuple[bool, Optional[dict]]:
    """
    Check if action_id is approved.
    Returns (is_approved, approval_row_or_None).
    Approval enforcement is ONLY here — the UI must not duplicate this gate.
    """
    row = get_approval(action_id, db_path)
    if row and row.get("decision") == "approved":
        return True, row
    return False, row
