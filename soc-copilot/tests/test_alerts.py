"""
tests/test_alerts.py - Phase 2 tests for manual alert ingestion.

Covers:
- POST /alerts assigns unique ID, appears in GET /alerts as origin=manual
- alerts.json is byte-identical after test
- Adding alert that shares entity/time window increases incident alert_count
- Stats match independent computation
- Validation: no entities, bad severity, bad source, bad ip → 422
- Approval anchor invalidation: shifting grouping → approval not carried, execute 403
- /decision for nonexistent action_id → 404
- DELETE: manual alert removed, seeded → 403, not found → 404, both audit events present
- summary_stale true after new alert joins incident with cached summary
"""
import hashlib
import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

import db as db_module
import pipeline as pipeline_module
import llm as llm_module


DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
ALERTS_JSON_PATH = os.path.join(DATA_DIR, "alerts.json")


def _file_sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def patch_db_path(tmp_path, monkeypatch):
    """Fresh temp DB for every test."""
    test_db = str(tmp_path / "test_alerts.db")
    monkeypatch.setattr(db_module, "DB_PATH", test_db)
    db_module.init_db(test_db)
    pipeline_module.invalidate_pipeline_cache()
    yield test_db
    pipeline_module.invalidate_pipeline_cache()


@pytest.fixture
def client(patch_db_path, monkeypatch, tmp_path):
    """Fresh TestClient with reset pipeline cache."""
    import api
    monkeypatch.setattr(db_module, "DB_PATH", patch_db_path)
    api._pipeline_cache = None
    pipeline_module._PIPELINE_CACHE = None
    with TestClient(api.app, raise_server_exceptions=True) as c:
        yield c


# ---------------------------------------------------------------------------
# Helper: minimal valid alert payload targeting priya.sharma (INC-1 user)
# ---------------------------------------------------------------------------

def _alert_payload(**overrides) -> dict:
    base = {
        "source": "identity",
        "severity": 2,
        "title": "Test alert - suspicious login",
        "description": "Suspicious login for priya.sharma",
        "user": "priya.sharma",
        "analyst": "test-analyst",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# 1. ID assignment, origin, alerts.json unchanged
# ---------------------------------------------------------------------------

class TestAlertAddBasic:
    def test_post_alert_returns_200(self, client):
        resp = client.post("/alerts", json=_alert_payload())
        assert resp.status_code == 200, resp.text

    def test_assigned_id_format(self, client):
        resp = client.post("/alerts", json=_alert_payload())
        alert = resp.json()["alert"]
        assert alert["id"].startswith("A-")
        num = int(alert["id"][2:])
        assert num > 0

    def test_id_is_unique_across_calls(self, client):
        r1 = client.post("/alerts", json=_alert_payload())
        r2 = client.post("/alerts", json=_alert_payload())
        id1 = r1.json()["alert"]["id"]
        id2 = r2.json()["alert"]["id"]
        assert id1 != id2

    def test_alert_appears_in_get_alerts_as_manual(self, client):
        r = client.post("/alerts", json=_alert_payload())
        alert_id = r.json()["alert"]["id"]
        get_r = client.get("/alerts?origin=manual")
        ids = [a["id"] for a in get_r.json()["alerts"]]
        assert alert_id in ids
        for a in get_r.json()["alerts"]:
            if a["id"] == alert_id:
                assert a["origin"] == "manual"

    def test_alerts_json_byte_identical_after_add(self, client):
        checksum_before = _file_sha256(ALERTS_JSON_PATH)
        client.post("/alerts", json=_alert_payload())
        checksum_after = _file_sha256(ALERTS_JSON_PATH)
        assert checksum_before == checksum_after, "alerts.json was modified!"

    def test_seeded_alerts_have_origin_seeded(self, client):
        r = client.get("/alerts?origin=seeded")
        alerts = r.json()["alerts"]
        assert len(alerts) > 0
        for a in alerts:
            assert a["origin"] == "seeded"


# ---------------------------------------------------------------------------
# 2. Adding alert that joins an incident changes alert_count and stats
# ---------------------------------------------------------------------------

class TestAlertJoinsIncident:
    def test_incident_alert_count_increases(self, client):
        # Get baseline for INC-1
        before = client.get("/incidents")
        inc1_before = next(
            i for i in before.json()["incidents"] if i["id"] == "INC-1"
        )
        count_before = inc1_before["alert_count"]

        # Add alert with priya.sharma in the same window as INC-1 alerts
        # INC-1 starts at 2024-10-10T08:00:00Z
        client.post("/alerts", json=_alert_payload(
            timestamp="2024-10-10T08:30:00Z"
        ))

        after = client.get("/incidents")
        # Find incident containing priya.sharma (may still be INC-1 or renumbered)
        inc_after = None
        for i in after.json()["incidents"]:
            if "priya.sharma" in [u for u in i["entities"].get("users", [])]:
                inc_after = i
                break

        assert inc_after is not None, "Could not find incident with priya.sharma after add"
        assert inc_after["alert_count"] > count_before

    def test_stats_match_independent_computation(self, client):
        # Add an alert that joins INC-1
        client.post("/alerts", json=_alert_payload(
            timestamp="2024-10-10T08:30:00Z"
        ))

        resp = client.get("/incidents")
        api_stats = resp.json()["stats"]

        # Independent computation from pipeline
        result = pipeline_module.build_pipeline()
        all_alerts = result["incidents"]  # only used for counts below
        # Recompute stats independently
        all_alerts_flat: list[dict] = []
        incident_ids: set[str] = set()
        for inc in result["incidents"]:
            for a in inc["alerts"]:
                all_alerts_flat.append(a)
                incident_ids.add(a["id"])
        for a in result["unlinked"]:
            all_alerts_flat.append(a)

        total = len(all_alerts_flat)
        noise = total - len(incident_ids)
        expected_noise_pct = round(noise / total * 100, 1) if total > 0 else 0.0

        assert api_stats["total_alerts"] == total
        assert api_stats["noise_reduction_pct"] == expected_noise_pct


# ---------------------------------------------------------------------------
# 3. Validation rejects bad inputs (422)
# ---------------------------------------------------------------------------

class TestAlertValidation:
    def test_no_entities_rejected(self, client):
        payload = {
            "source": "siem",
            "severity": 2,
            "title": "Test",
            "analyst": "analyst-1",
            # no user/host/ip/resource
        }
        resp = client.post("/alerts", json=payload)
        assert resp.status_code == 422

    def test_bad_severity_rejected(self, client):
        resp = client.post("/alerts", json=_alert_payload(severity=5))
        assert resp.status_code == 422

    def test_severity_0_rejected(self, client):
        resp = client.post("/alerts", json=_alert_payload(severity=0))
        assert resp.status_code == 422

    def test_bad_source_rejected(self, client):
        resp = client.post("/alerts", json=_alert_payload(source="firewall"))
        assert resp.status_code == 422

    def test_invalid_ip_rejected(self, client):
        resp = client.post("/alerts", json=_alert_payload(ip="not-an-ip"))
        assert resp.status_code == 422

    def test_valid_ipv4_accepted(self, client):
        resp = client.post("/alerts", json=_alert_payload(ip="1.2.3.4"))
        assert resp.status_code == 200

    def test_valid_ipv6_accepted(self, client):
        resp = client.post("/alerts", json=_alert_payload(ip="2001:db8::1"))
        assert resp.status_code == 200

    def test_empty_title_rejected(self, client):
        resp = client.post("/alerts", json=_alert_payload(title=""))
        assert resp.status_code == 422

    def test_empty_analyst_rejected(self, client):
        resp = client.post("/alerts", json=_alert_payload(analyst=""))
        assert resp.status_code == 422

    def test_bad_timestamp_rejected(self, client):
        resp = client.post("/alerts", json=_alert_payload(timestamp="not-a-date"))
        assert resp.status_code == 422

    def test_valid_timestamp_accepted(self, client):
        resp = client.post("/alerts", json=_alert_payload(timestamp="2024-10-10T08:30:00Z"))
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 4. Anchor invalidation: approval doesn't carry over after regrouping
# ---------------------------------------------------------------------------

class TestAnchorInvalidation:
    def test_approval_invalidated_after_alert_changes_grouping(self, client):
        """
        Approve an action on INC-1, then add an alert that changes its grouping
        (potentially renumbering incidents), then confirm execute returns 403.

        Strategy: add an alert with a different user in the same time window,
        which may merge two incidents or change INC-1's anchor. Either way,
        the stored anchor won't match the new current anchor → execute blocked.
        """
        # Get INC-1's first action_id
        inc_resp = client.get("/incidents/INC-1")
        assert inc_resp.status_code == 200
        action_cards = inc_resp.json()["action_cards"]
        if not action_cards:
            pytest.skip("INC-1 has no action cards")

        action_id = action_cards[0]["action_id"]

        # Approve the action
        dec_resp = client.post(
            f"/actions/{action_id}/decision",
            json={"decision": "approved", "analyst": "analyst-1"},
        )
        assert dec_resp.status_code == 200

        # Confirm execute works now
        exec_resp = client.post(f"/actions/{action_id}/execute", params={"analyst": "analyst-1"})
        assert exec_resp.status_code == 200

        # Add an alert that shares the same user (priya.sharma) very early,
        # which will change INC-1's alert list and thus its anchor
        client.post("/alerts", json=_alert_payload(
            timestamp="2024-10-10T07:00:00Z",  # BEFORE existing alerts → becomes new earliest
            severity=1,
        ))

        # After the new alert, re-get INC-1 (or whichever incident has priya.sharma)
        # The action may now belong to a different incident or have a different anchor
        # Execute should now be blocked (anchor changed)
        exec_resp2 = client.post(f"/actions/{action_id}/execute", params={"analyst": "analyst-1"})
        # Either 403 (anchor mismatch) or 404 (incident renumbered, action not found)
        assert exec_resp2.status_code in (403, 404), (
            f"Expected 403 or 404 after anchor change, got {exec_resp2.status_code}: {exec_resp2.text}"
        )

    def test_decision_for_nonexistent_action_returns_404(self, client):
        resp = client.post(
            "/actions/INC-99-S99/decision",
            json={"decision": "approved", "analyst": "analyst-1"},
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 5. DELETE /alerts
# ---------------------------------------------------------------------------

class TestDeleteAlert:
    def test_delete_manual_alert_succeeds(self, client):
        add_r = client.post("/alerts", json=_alert_payload())
        alert_id = add_r.json()["alert"]["id"]
        del_r = client.delete(f"/alerts/{alert_id}", params={"analyst": "analyst-1"})
        assert del_r.status_code == 200
        assert del_r.json()["deleted"] == alert_id

    def test_deleted_alert_not_in_list(self, client):
        add_r = client.post("/alerts", json=_alert_payload())
        alert_id = add_r.json()["alert"]["id"]
        client.delete(f"/alerts/{alert_id}", params={"analyst": "analyst-1"})
        get_r = client.get("/alerts?origin=manual")
        ids = [a["id"] for a in get_r.json()["alerts"]]
        assert alert_id not in ids

    def test_delete_seeded_alert_returns_403(self, client):
        resp = client.delete("/alerts/A-001", params={"analyst": "analyst-1"})
        assert resp.status_code == 403

    def test_delete_nonexistent_manual_alert_returns_404(self, client):
        resp = client.delete("/alerts/A-9999", params={"analyst": "analyst-1"})
        assert resp.status_code == 404

    def test_add_and_remove_appear_in_audit_log(self, client, patch_db_path):
        add_r = client.post("/alerts", json=_alert_payload())
        alert_id = add_r.json()["alert"]["id"]
        client.delete(f"/alerts/{alert_id}", params={"analyst": "analyst-1"})

        logs = db_module.get_audit_log(patch_db_path)
        events = [r["event"] for r in logs]
        assert "ALERT_ADDED" in events
        assert "ALERT_REMOVED" in events

    def test_delete_restores_stats_to_baseline(self, client):
        baseline = client.get("/incidents").json()["stats"]

        add_r = client.post("/alerts", json=_alert_payload(
            timestamp="2024-10-10T08:30:00Z"
        ))
        alert_id = add_r.json()["alert"]["id"]

        del_r = client.delete(f"/alerts/{alert_id}", params={"analyst": "analyst-1"})
        restored_stats = del_r.json()["stats"]

        assert restored_stats == baseline

    def test_alerts_json_unchanged_after_delete(self, client):
        checksum_before = _file_sha256(ALERTS_JSON_PATH)
        add_r = client.post("/alerts", json=_alert_payload())
        alert_id = add_r.json()["alert"]["id"]
        client.delete(f"/alerts/{alert_id}", params={"analyst": "analyst-1"})
        checksum_after = _file_sha256(ALERTS_JSON_PATH)
        assert checksum_before == checksum_after, "alerts.json was modified!"


# ---------------------------------------------------------------------------
# 6. summary_stale flag
# ---------------------------------------------------------------------------

class TestSummaryStale:
    def test_summary_stale_false_when_no_change(self, tmp_path, monkeypatch):
        """summary_stale=False when incident hasn't changed since caching."""
        import api
        monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "test.db"))
        db_module.init_db()
        api._pipeline_cache = None
        pipeline_module._PIPELINE_CACHE = None

        result = pipeline_module.build_pipeline()
        inc = result["incidents"][0]

        # Build and save a fake cache entry with the CURRENT hash
        payload = llm_module._build_payload(inc)
        current_hash = llm_module._hash_payload(payload)
        fake_response = {"status": "ok", "summary": "Test summary [A-001]"}
        llm_module._save_cache(inc["id"], fake_response, current_hash)

        loaded = llm_module.load_cached_summary(inc["id"], incident=inc)
        assert loaded is not None
        assert loaded.get("summary_stale") is False

    def test_summary_stale_true_after_alert_added(self, tmp_path, monkeypatch):
        """summary_stale=True when incident changes after summary was cached."""
        import api
        monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "test2.db"))
        db_module.init_db()
        api._pipeline_cache = None
        pipeline_module._PIPELINE_CACHE = None

        # Get INC-1 and cache a summary for its CURRENT hash
        result = pipeline_module.build_pipeline()
        inc = result["incidents"][0]  # INC-1 (highest score)

        payload = llm_module._build_payload(inc)
        original_hash = llm_module._hash_payload(payload)
        fake_response = {"status": "ok", "summary": "Old summary [A-001]"}
        llm_module._save_cache(inc["id"], fake_response, original_hash)

        # Add a manual alert that joins INC-1 (same user, within window)
        db_module.insert_manual_alert(
            "A-999",
            {
                "id": "A-999",
                "timestamp": "2024-10-10T08:30:00Z",
                "source": "identity",
                "severity": 2,
                "title": "Extra alert",
                "description": "Extra",
                "user": "priya.sharma",
                "host": None,
                "ip": None,
                "resource": None,
                "raw": None,
                "origin": "manual",
            },
            "test-analyst",
        )
        pipeline_module.invalidate_pipeline_cache()
        api._pipeline_cache = None

        # Reload the incident (now has A-999)
        result2 = pipeline_module.build_pipeline()
        inc2 = next(
            i for i in result2["incidents"]
            if inc["id"] in i["id"] or any("priya.sharma" in (a.get("user") or "") for a in i["alerts"])
        )

        # Load the cached summary with the NEW incident — should be stale
        loaded = llm_module.load_cached_summary(inc["id"], incident=inc2)
        assert loaded is not None
        assert loaded.get("summary_stale") is True
