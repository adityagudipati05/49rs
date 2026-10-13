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
import llm as llm_module


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


# ---------------------------------------------------------------------------
# Task 1: Stuck summary refresh
# ---------------------------------------------------------------------------

class TestSummaryRefreshBug:
    def test_summary_refresh_after_failure_fixed(self, client, monkeypatch):
        # 1. With no key, POST /summary returns status "unavailable"
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        resp1 = client.post("/incidents/INC-1/summary")
        assert resp1.status_code == 200
        summary1 = resp1.json()["summary"]
        assert summary1.get("status") == "unavailable"

        # 2. Mock llm_module._call_api to return a valid summary dict
        mock_payload = {
            "title": "Compromised Account Priya",
            "summary": "User priya.sharma performed impossible travel [A-001].",
            "timeline": [],
            "recommended_playbook": "compromised_account",
            "playbook_reasoning": "Identity alerts",
            "confidence": "high",
            "unknowns": [],
        }
        monkeypatch.setattr(llm_module, "_call_api", lambda incident: mock_payload)

        # POST /summary again must return the valid summary, not "unavailable"
        resp2 = client.post("/incidents/INC-1/summary")
        assert resp2.status_code == 200
        summary2 = resp2.json()["summary"]
        assert summary2.get("title") == "Compromised Account Priya"
        assert summary2.get("status") != "unavailable"


# ---------------------------------------------------------------------------
# Task 3: Deterministic prompt injection detection
# ---------------------------------------------------------------------------

class TestPromptInjectionDetection:
    def test_inc2_reports_a007_injection(self, client):
        resp = client.get("/incidents/INC-2")
        assert resp.status_code == 200
        data = resp.json()
        findings = data.get("injection_findings")
        assert isinstance(findings, list)
        alert_ids = [f["alert_id"] for f in findings]
        assert "A-007" in alert_ids

    def test_inc1_and_inc3_report_empty_injection(self, client):
        for inc_id in ["INC-1", "INC-3"]:
            resp = client.get(f"/incidents/{inc_id}")
            assert resp.status_code == 200
            data = resp.json()
            findings = data.get("injection_findings")
            assert findings == []


# ---------------------------------------------------------------------------
# Task 4: Deterministic timeline fallback
# ---------------------------------------------------------------------------

class TestTimelineBasicFallback:
    def test_timeline_basic_with_no_api_key(self, client, monkeypatch):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        resp = client.get("/incidents/INC-1")
        assert resp.status_code == 200
        data = resp.json()
        tb = data.get("timeline_basic")
        assert isinstance(tb, list)
        assert len(tb) == 5
        # Verify sorted ascending by timestamp
        timestamps = [e["time"] for e in tb]
        assert timestamps == sorted(timestamps)
        # Verify attack_stage is null
        for e in tb:
            assert e["attack_stage"] is None


# ---------------------------------------------------------------------------
# Task 5: Case note export
# ---------------------------------------------------------------------------

class TestCaseNoteExport:
    def test_case_note_headings_order_with_and_without_summary(self, client, monkeypatch):
        expected_headings = [
            "## Risk",
            "## Summary",
            "## Timeline",
            "## Context",
            "## Recommended playbook",
            "## Actions and decisions",
            "## Unknowns and injection findings",
            "## Validation",
        ]

        # 1. Without summary (or unavailable)
        resp1 = client.get("/incidents/INC-1/case-note")
        assert resp1.status_code == 200
        md1 = resp1.json()["markdown"]
        assert md1.startswith("# ")
        assert "Synthetic data. Execution is simulated." in md1

        indices1 = [md1.find(h) for h in expected_headings]
        assert all(idx != -1 for idx in indices1), f"Missing headings in md1: {md1}"
        assert indices1 == sorted(indices1), "Headings not in expected order without summary"

        # 2. With summary
        mock_payload = {
            "title": "Compromised Account Priya",
            "summary": "User priya.sharma performed impossible travel [A-001].",
            "timeline": [{"time": "2024-10-10T08:00:00Z", "event": "Travel", "source_id": "A-001", "attack_stage": "initial-access"}],
            "recommended_playbook": "compromised_account",
            "playbook_reasoning": "Identity alerts",
            "confidence": "high",
            "unknowns": ["Unknown IP owner"],
        }
        monkeypatch.setattr(llm_module, "load_cached_summary", lambda inc_id, incident=None: mock_payload)

        resp2 = client.get("/incidents/INC-1/case-note")
        assert resp2.status_code == 200
        md2 = resp2.json()["markdown"]
        assert "# Compromised Account Priya" in md2
        indices2 = [md2.find(h) for h in expected_headings]
        assert all(idx != -1 for idx in indices2), f"Missing headings in md2: {md2}"
        assert indices2 == sorted(indices2), "Headings not in expected order with summary"

