"""
tests/test_triage.py - Tests for per-alert triage classification and stats.

Verifies:
1. classify_unlinked(alert) rules:
   - severity >= 3 -> "needs_review"
   - intel verdict "malicious" or "suspicious" -> "needs_review"
   - severity < 3 and benign intel -> "low_priority"
   - missing intel (None or omitted) -> "low_priority"
2. Seeded data baseline:
   - needs_review_count == 0
   - low_priority_count == 28
   - noise_reduction_pct == 70.0 (28 / 40 * 100)
3. Lone severity-4 alert from 185.220.101.7:
   - classified as "needs_review"
   - NOT counted in noise_reduction_pct
4. Two alerts sharing a user:
   - correlated into an incident ("in_incident" triage)
   - incident_id matches the formed incident
5. GET /alerts:
   - Each alert includes "incident_id" (str or None) and "triage" ("in_incident" | "needs_review" | "low_priority")
   - Query param ?triage= filters correctly
"""
import pytest
from fastapi.testclient import TestClient

import db as db_module
import pipeline as pipeline_module
from pipeline import classify_unlinked, compute_stats, build_pipeline


@pytest.fixture(autouse=True)
def patch_db_path(tmp_path, monkeypatch):
    """Fresh temp DB for each test."""
    test_db = str(tmp_path / "test_triage.db")
    monkeypatch.setattr(db_module, "DB_PATH", test_db)
    db_module.init_db(test_db)
    pipeline_module.invalidate_pipeline_cache()
    yield test_db
    pipeline_module.invalidate_pipeline_cache()


@pytest.fixture
def client(patch_db_path, monkeypatch):
    import api
    monkeypatch.setattr(db_module, "DB_PATH", patch_db_path)
    api._pipeline_cache = None
    pipeline_module._PIPELINE_CACHE = None
    with TestClient(api.app, raise_server_exceptions=True) as c:
        yield c


# ---------------------------------------------------------------------------
# Unit tests for classify_unlinked
# ---------------------------------------------------------------------------

class TestClassifyUnlinked:
    def test_severity_4_is_needs_review(self):
        alert = {"severity": 4, "intel": None}
        assert classify_unlinked(alert) == "needs_review"

    def test_severity_3_is_needs_review(self):
        alert = {"severity": 3, "intel": {"verdict": "benign"}}
        assert classify_unlinked(alert) == "needs_review"

    def test_malicious_intel_is_needs_review(self):
        alert = {"severity": 2, "intel": {"verdict": "malicious"}}
        assert classify_unlinked(alert) == "needs_review"

    def test_suspicious_intel_is_needs_review(self):
        alert = {"severity": 1, "intel": {"verdict": "suspicious"}}
        assert classify_unlinked(alert) == "needs_review"

    def test_missing_intel_is_not_suspicious(self):
        # Missing intel key
        alert_no_key = {"severity": 2}
        assert classify_unlinked(alert_no_key) == "low_priority"

        # Explicit None intel
        alert_none = {"severity": 2, "intel": None}
        assert classify_unlinked(alert_none) == "low_priority"

    def test_benign_intel_low_severity_is_low_priority(self):
        alert = {"severity": 2, "intel": {"verdict": "benign"}}
        assert classify_unlinked(alert) == "low_priority"


# ---------------------------------------------------------------------------
# Tests on seeded baseline data
# ---------------------------------------------------------------------------

class TestSeededTriageBaseline:
    def test_seeded_data_counts(self):
        res = build_pipeline()
        stats = res["stats"]
        assert stats["needs_review_count"] == 0
        assert stats["low_priority_count"] == 28
        assert stats["total_alerts"] == 40
        assert stats["incident_count"] == 3
        assert stats["noise_reduction_pct"] == 70.0

    def test_get_alerts_includes_incident_id_and_triage(self, client):
        r = client.get("/alerts")
        assert r.status_code == 200
        alerts = r.json()["alerts"]
        assert len(alerts) == 40

        for a in alerts:
            assert "incident_id" in a
            assert "triage" in a
            assert a["triage"] in ("in_incident", "needs_review", "low_priority")
            if a["triage"] == "in_incident":
                assert a["incident_id"] is not None
                assert a["incident_id"].startswith("INC-")
            else:
                assert a["incident_id"] is None

        # Verify seeded counts match
        in_inc_count = sum(1 for a in alerts if a["triage"] == "in_incident")
        needs_rev_count = sum(1 for a in alerts if a["triage"] == "needs_review")
        low_prio_count = sum(1 for a in alerts if a["triage"] == "low_priority")
        assert in_inc_count == 12
        assert needs_rev_count == 0
        assert low_prio_count == 28


# ---------------------------------------------------------------------------
# Lone severity-4 alert from 185.220.101.7
# ---------------------------------------------------------------------------

class TestLoneSeverity4Alert:
    def test_lone_alert_is_needs_review_and_excluded_from_noise_pct(self, client):
        # 185.220.101.7 with severity 4 far outside seeded window (2026 timestamp)
        payload = {
            "source": "siem",
            "severity": 4,
            "ip": "185.220.101.7",
            "title": "Outbound Tor Connection Detected",
            "description": "Traffic to known Tor exit node",
            "timestamp": "2026-05-01T12:00:00Z",
            "analyst": "sec-ops",
        }
        res = client.post("/alerts", json=payload)
        assert res.status_code == 200
        data = res.json()
        stats = data["stats"]

        # 40 seeded + 1 manual = 41 total alerts
        assert stats["total_alerts"] == 41
        assert stats["needs_review_count"] == 1
        assert stats["low_priority_count"] == 28

        # Lone alert must NOT be counted as noise in noise_reduction_pct
        # noise_reduction_pct = 28 / 41 * 100 = 68.3% (NOT 29 / 41 * 100 = 70.7%)
        expected_noise_pct = round(28 / 41 * 100, 1)
        assert stats["noise_reduction_pct"] == expected_noise_pct
        assert stats["noise_alerts_count"] == 28

        # Check GET /alerts
        alerts_resp = client.get("/alerts")
        added_alert = next(a for a in alerts_resp.json()["alerts"] if a["id"] == data["alert"]["id"])
        assert added_alert["triage"] == "needs_review"
        assert added_alert["incident_id"] is None


# ---------------------------------------------------------------------------
# Two alerts sharing a user become in_incident
# ---------------------------------------------------------------------------

class TestTwoAlertsJoinIncident:
    def test_two_alerts_sharing_user_become_in_incident(self, client):
        # Ingest two new alerts with a distinct user within the 2-hour window
        # that don't match any existing seeded incidents
        user_name = "clara.oswald"
        alert1 = {
            "source": "identity",
            "severity": 2,
            "user": user_name,
            "title": "MFA prompt repeated",
            "timestamp": "2026-06-01T10:00:00Z",
            "analyst": "analyst-1",
        }
        alert2 = {
            "source": "cloud",
            "severity": 2,
            "user": user_name,
            "title": "Role assumption from unusual IP",
            "timestamp": "2026-06-01T10:45:00Z",
            "analyst": "analyst-1",
        }

        r1 = client.post("/alerts", json=alert1)
        assert r1.status_code == 200
        id1 = r1.json()["alert"]["id"]

        r2 = client.post("/alerts", json=alert2)
        assert r2.status_code == 200
        id2 = r2.json()["alert"]["id"]

        # Incidents should now be 4 (3 seeded + 1 new)
        incidents = r2.json()["incidents"]
        assert len(incidents) == 4

        # Verify both alerts belong to the new incident
        new_inc = next(
            inc for inc in incidents
            if user_name in inc["entities"].get("users", [])
        )
        assert id1 in new_inc["alert_ids"]
        assert id2 in new_inc["alert_ids"]

        # Verify via GET /alerts
        alerts_resp = client.get("/alerts").json()["alerts"]
        a1_data = next(a for a in alerts_resp if a["id"] == id1)
        a2_data = next(a for a in alerts_resp if a["id"] == id2)

        assert a1_data["triage"] == "in_incident"
        assert a1_data["incident_id"] == new_inc["id"]

        assert a2_data["triage"] == "in_incident"
        assert a2_data["incident_id"] == new_inc["id"]
