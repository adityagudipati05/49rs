"""
tests/test_api.py - Tests for the FastAPI backend endpoints.

Tests:
- execute without decision → 403
- approve then execute → 200
- reject then execute → 403
- audit log persists after DB reconnect
"""
import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

import db as db_module


# ---------------------------------------------------------------------------
# Override DB path for testing
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def patch_db_path(tmp_path, monkeypatch):
    """Use a fresh temp DB for each test."""
    test_db = str(tmp_path / "test_api.db")
    monkeypatch.setattr(db_module, "DB_PATH", test_db)
    db_module.init_db(test_db)
    yield test_db


@pytest.fixture
def client(patch_db_path, monkeypatch):
    import api
    import db as db_mod
    # DB_PATH is now resolved dynamically, so monkeypatch works
    monkeypatch.setattr(db_mod, "DB_PATH", patch_db_path)
    # Reset pipeline cache for test isolation
    api._pipeline_cache = None
    with TestClient(api.app, raise_server_exceptions=True) as c:
        yield c


# ---------------------------------------------------------------------------
# Execute without decision → 403
# ---------------------------------------------------------------------------

class TestExecuteWithoutApproval:
    def test_execute_without_decision_gives_403(self, client):
        response = client.post("/actions/INC-1-S1/execute", params={"analyst": "tester"})
        assert response.status_code == 403, (
            f"Expected 403, got {response.status_code}: {response.text}"
        )

    def test_403_response_has_blocked_message(self, client):
        response = client.post("/actions/INC-1-S1/execute", params={"analyst": "tester"})
        body = response.json()
        assert "detail" in body
        detail = body["detail"]
        # detail may be a dict or a string
        if isinstance(detail, dict):
            assert "blocked" in str(detail).lower() or "not been approved" in str(detail).lower()
        else:
            assert "blocked" in detail.lower() or "not approved" in detail.lower()

    def test_blocked_attempt_is_logged(self, client, patch_db_path):
        client.post("/actions/INC-1-S1/execute", params={"analyst": "tester"})
        logs = db_module.get_audit_log(patch_db_path)
        events = [r["event"] for r in logs]
        assert "EXECUTION_BLOCKED" in events


# ---------------------------------------------------------------------------
# Approve then execute → 200
# ---------------------------------------------------------------------------

class TestApproveAndExecute:
    def test_approve_then_execute_gives_200(self, client):
        # Approve first
        approve_resp = client.post(
            "/actions/INC-1-S1/decision",
            json={"decision": "approved", "analyst": "alice", "comment": "LGTM"},
        )
        assert approve_resp.status_code == 200

        # Now execute
        exec_resp = client.post("/actions/INC-1-S1/execute", params={"analyst": "alice"})
        assert exec_resp.status_code == 200

    def test_execute_response_is_simulated(self, client):
        client.post(
            "/actions/INC-1-S1/decision",
            json={"decision": "approved", "analyst": "alice"},
        )
        resp = client.post("/actions/INC-1-S1/execute", params={"analyst": "alice"})
        body = resp.json()
        assert "simulated" in body["status"].lower()
        assert "Simulated" in body.get("label", "")

    def test_execute_logs_executed_simulated(self, client, patch_db_path):
        client.post(
            "/actions/INC-1-S1/decision",
            json={"decision": "approved", "analyst": "alice"},
        )
        client.post("/actions/INC-1-S1/execute", params={"analyst": "alice"})
        logs = db_module.get_audit_log(patch_db_path)
        events = [r["event"] for r in logs]
        assert "EXECUTED_SIMULATED" in events


# ---------------------------------------------------------------------------
# Reject then execute → 403
# ---------------------------------------------------------------------------

class TestRejectAndExecute:
    def test_reject_then_execute_gives_403(self, client):
        # Reject first
        client.post(
            "/actions/INC-1-S1/decision",
            json={"decision": "rejected", "analyst": "bob", "comment": "Not verified"},
        )
        # Execute should be blocked
        exec_resp = client.post("/actions/INC-1-S1/execute", params={"analyst": "bob"})
        assert exec_resp.status_code == 403

    def test_reject_logs_decision(self, client, patch_db_path):
        client.post(
            "/actions/INC-1-S1/decision",
            json={"decision": "rejected", "analyst": "bob"},
        )
        logs = db_module.get_audit_log(patch_db_path)
        events = [r["event"] for r in logs]
        assert "DECISION_REJECTED" in events


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

class TestInputValidation:
    def test_invalid_decision_value_rejected(self, client):
        resp = client.post(
            "/actions/INC-1-S1/decision",
            json={"decision": "maybe", "analyst": "alice"},
        )
        assert resp.status_code == 422

    def test_empty_analyst_rejected(self, client):
        resp = client.post(
            "/actions/INC-1-S1/decision",
            json={"decision": "approved", "analyst": ""},
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Audit log persists after DB reconnect
# ---------------------------------------------------------------------------

class TestAuditLogPersistence:
    def test_audit_log_persists_after_reconnect(self, client, patch_db_path):
        # Write an event
        client.post(
            "/actions/INC-1-S1/decision",
            json={"decision": "approved", "analyst": "persist-test"},
        )

        # Read directly from DB (simulates reconnect)
        logs = db_module.get_audit_log(patch_db_path)
        events = [r["event"] for r in logs]
        assert "DECISION_APPROVED" in events

    def test_audit_log_is_append_only(self, client, patch_db_path):
        """Each action adds a new row — no rows are deleted or overwritten."""
        client.post(
            "/actions/INC-1-S1/decision",
            json={"decision": "approved", "analyst": "a1"},
        )
        client.post(
            "/actions/INC-1-S1/decision",
            json={"decision": "rejected", "analyst": "a2"},
        )
        logs = db_module.get_audit_log(patch_db_path)
        events = [r["event"] for r in logs]
        # Both events should be present (append-only)
        assert "DECISION_APPROVED" in events
        assert "DECISION_REJECTED" in events
        assert len(logs) >= 2
