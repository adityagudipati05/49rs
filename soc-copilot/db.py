"""
db.py - SQLite initialization and helpers for approvals, audit_log, and manual_alerts.

Schema:
  approvals(action_id PK, decision, analyst, timestamp, evidence_ids, comment, incident_anchor)
  audit_log(id INTEGER PK AUTOINCREMENT, timestamp, analyst, event, action_id, details)
  manual_alerts(id TEXT PK, payload TEXT, created_at TEXT, created_by TEXT)

The audit log is append-only and written only by real events.
incident_anchor stores the earliest alert ID of the incident when an approval is recorded,
so that we can detect when an alert change has caused incident re-grouping.
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
    """Create tables if they don't exist. Idempotent. Migrates approvals safely."""
    conn = get_connection(db_path)
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS approvals (
                action_id   TEXT PRIMARY KEY,
                decision    TEXT NOT NULL CHECK(decision IN ('approved', 'rejected')),
                analyst     TEXT NOT NULL,
                timestamp   TEXT NOT NULL,
                evidence_ids TEXT,
                comment     TEXT,
                incident_anchor TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                analyst     TEXT NOT NULL,
                event       TEXT NOT NULL,
                action_id   TEXT,
                details     TEXT
            );

            CREATE TABLE IF NOT EXISTS manual_alerts (
                id          TEXT PRIMARY KEY,
                payload     TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                created_by  TEXT NOT NULL
            );
        """)
        conn.commit()

        # Safe migration: add incident_anchor column to approvals if missing.
        # Old rows get NULL (treated as pending in anchor-check logic).
        cols = [
            row[1] for row in conn.execute("PRAGMA table_info(approvals)").fetchall()
        ]
        if "incident_anchor" not in cols:
            conn.execute("ALTER TABLE approvals ADD COLUMN incident_anchor TEXT")
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
    incident_anchor: Optional[str] = None,
    db_path: Optional[str] = None,
) -> None:
    """Insert or replace an approval record, storing the incident anchor."""
    conn = get_connection(db_path)
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO approvals
                (action_id, decision, analyst, timestamp, evidence_ids, comment, incident_anchor)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                action_id,
                decision,
                analyst,
                _now_iso(),
                json.dumps(evidence_ids) if evidence_ids else None,
                comment,
                incident_anchor,
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


def require_approved_with_anchor(
    action_id: str,
    current_anchor: Optional[str],
    db_path: Optional[str] = None,
) -> tuple[bool, Optional[dict], str]:
    """
    Check if action_id is approved AND the stored anchor matches current_anchor.
    Returns (is_approved, approval_row_or_None, reason_if_blocked).

    - NULL stored anchor → treat as pending (do not guess).
    - Non-matching anchor → approval invalidated by incident change.
    """
    row = get_approval(action_id, db_path)
    if not row:
        return False, None, "no_approval_record"

    if row.get("decision") != "approved":
        return False, row, "not_approved"

    stored_anchor = row.get("incident_anchor")
    if stored_anchor is None:
        # Legacy NULL anchor: treat as pending
        return False, row, "null_anchor_legacy"

    if stored_anchor != current_anchor:
        return False, row, "approval no longer matches incident (alerts changed)"

    return True, row, ""


# ---------------------------------------------------------------------------
# Manual alerts helpers
# ---------------------------------------------------------------------------

def insert_manual_alert(
    alert_id: str,
    payload: dict,
    created_by: str,
    db_path: Optional[str] = None,
) -> None:
    """Insert a manual alert row."""
    conn = get_connection(db_path)
    try:
        conn.execute(
            """
            INSERT INTO manual_alerts (id, payload, created_at, created_by)
            VALUES (?, ?, ?, ?)
            """,
            (alert_id, json.dumps(payload, ensure_ascii=False), _now_iso(), created_by),
        )
        conn.commit()
    finally:
        conn.close()


def get_manual_alerts(db_path: Optional[str] = None) -> list[dict]:
    """Return all manual alerts as parsed dicts, newest first."""
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT id, payload, created_at, created_by FROM manual_alerts ORDER BY created_at DESC"
        ).fetchall()
        result = []
        for row in rows:
            alert = json.loads(row["payload"])
            alert["created_at"] = row["created_at"]
            alert["created_by"] = row["created_by"]
            result.append(alert)
        return result
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def delete_manual_alert(alert_id: str, db_path: Optional[str] = None) -> bool:
    """Delete a manual alert by ID. Returns True if a row was deleted."""
    conn = get_connection(db_path)
    try:
        cur = conn.execute("DELETE FROM manual_alerts WHERE id = ?", (alert_id,))
        conn.commit()
        return cur.rowcount > 0
    except sqlite3.OperationalError:
        return False
    finally:
        conn.close()


def manual_alert_exists(alert_id: str, db_path: Optional[str] = None) -> bool:
    """Return True if a manual alert with that ID exists."""
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT 1 FROM manual_alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        return row is not None
    except sqlite3.OperationalError:
        return False
    finally:
        conn.close()


def next_alert_id(seeded_ids: list[str], db_path: Optional[str] = None) -> str:
    """
    Compute the next free A-NNN ID across seeded + manual alerts.
    Format: A-NNN (3+ digits). The server assigns IDs; clients never choose them.
    """
    # Gather all existing numeric suffixes
    all_ids = list(seeded_ids)
    conn = get_connection(db_path)
    try:
        rows = conn.execute("SELECT id FROM manual_alerts").fetchall()
        all_ids.extend(row["id"] for row in rows)
    except sqlite3.OperationalError:
        pass
    finally:
        conn.close()

    max_num = 0
    for aid in all_ids:
        if isinstance(aid, str) and aid.startswith("A-"):
            try:
                n = int(aid[2:])
                if n > max_num:
                    max_num = n
            except ValueError:
                pass

    next_num = max_num + 1
    # Use 3 digits minimum, grow as needed
    width = max(3, len(str(next_num)))
    return f"A-{str(next_num).zfill(width)}"
