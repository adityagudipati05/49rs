"""
tests/test_pipeline.py - Tests for correlation, scoring, and noise reduction stats.
"""
import pytest


# ---------------------------------------------------------------------------
# Expected alert IDs for each attack story (from generate_data.py)
# ---------------------------------------------------------------------------
ATTACK1_IDS = {"A-001", "A-002", "A-003", "A-004", "A-005"}  # account takeover
ATTACK2_IDS = {"A-006", "A-007", "A-008", "A-009"}           # malware host
ATTACK3_IDS = {"A-010", "A-011", "A-012"}                    # cloud exposure


def _find_incident_by_alerts(incidents, expected_ids):
    """Return the first incident whose alert_ids match exactly the expected set."""
    for inc in incidents:
        if set(inc["alert_ids"]) == expected_ids:
            return inc
    return None


# ---------------------------------------------------------------------------
# Correlation tests
# ---------------------------------------------------------------------------

class TestCorrelation:
    def test_exactly_three_incidents(self, incidents):
        """Exactly 3 incidents must be produced."""
        assert len(incidents) == 3, (
            f"Expected 3 incidents, got {len(incidents)}: "
            f"{[i['id'] for i in incidents]}"
        )

    def test_attack1_incident_exists(self, incidents):
        """Account takeover alerts A-001..A-005 form one incident."""
        inc = _find_incident_by_alerts(incidents, ATTACK1_IDS)
        assert inc is not None, (
            f"No incident with alert IDs {ATTACK1_IDS}. "
            f"Got: {[set(i['alert_ids']) for i in incidents]}"
        )

    def test_attack2_incident_exists(self, incidents):
        """Malware alerts A-006..A-009 form one incident."""
        inc = _find_incident_by_alerts(incidents, ATTACK2_IDS)
        assert inc is not None, (
            f"No incident with alert IDs {ATTACK2_IDS}. "
            f"Got: {[set(i['alert_ids']) for i in incidents]}"
        )

    def test_attack3_incident_exists(self, incidents):
        """Cloud exposure alerts A-010..A-012 form one incident."""
        inc = _find_incident_by_alerts(incidents, ATTACK3_IDS)
        assert inc is not None, (
            f"No incident with alert IDs {ATTACK3_IDS}. "
            f"Got: {[set(i['alert_ids']) for i in incidents]}"
        )

    def test_noise_stays_unlinked(self, incidents, unlinked):
        """No noise alert (A-013+) should appear in any incident."""
        attack_ids = ATTACK1_IDS | ATTACK2_IDS | ATTACK3_IDS
        for inc in incidents:
            noise_in_inc = set(inc["alert_ids"]) - attack_ids
            assert not noise_in_inc, (
                f"Noise alerts {noise_in_inc} were incorrectly merged into {inc['id']}"
            )

    def test_attack_alerts_not_in_unlinked(self, unlinked):
        """No attack alert should be in the unlinked list."""
        attack_ids = ATTACK1_IDS | ATTACK2_IDS | ATTACK3_IDS
        unlinked_ids = {a["id"] for a in unlinked}
        overlap = attack_ids & unlinked_ids
        assert not overlap, f"Attack alerts found in unlinked: {overlap}"


# ---------------------------------------------------------------------------
# Scoring tests
# ---------------------------------------------------------------------------

class TestScoring:
    def test_scoring_is_deterministic(self, incidents):
        """Running score_incident twice on the same data yields the same result."""
        from pipeline import score_incident
        for inc in incidents:
            s1, l1, r1 = score_incident(inc)
            s2, l2, r2 = score_incident(inc)
            assert s1 == s2
            assert l1 == l2
            assert r1 == r2

    def test_reasons_reference_actual_values(self, incidents):
        """Each reason string must contain at least one real numeric value from the data."""
        import re
        for inc in incidents:
            for reason in inc["reasons"]:
                # Should contain a number (score, criticality, privilege, count, etc.)
                assert re.search(r"\d+", reason), (
                    f"Reason '{reason}' in {inc['id']} contains no numeric value — "
                    "may be a hardcoded generic string."
                )

    def test_incidents_sorted_by_score_descending(self, incidents):
        scores = [inc["score"] for inc in incidents]
        assert scores == sorted(scores, reverse=True), (
            f"Incidents not sorted by score desc: {scores}"
        )

    def test_labels_match_scores(self, incidents):
        """Labels must be derived from the actual score thresholds."""
        for inc in incidents:
            score = inc["score"]
            expected = (
                "Critical" if score >= 14 else
                "High" if score >= 10 else
                "Medium" if score >= 6 else
                "Low"
            )
            assert inc["label"] == expected, (
                f"{inc['id']}: score={score} expected label={expected} got={inc['label']}"
            )

    def test_malware_incident_has_malicious_intel_reason(self, incidents):
        """The malware incident must have a reason mentioning malicious intel."""
        inc = _find_incident_by_alerts(incidents, ATTACK2_IDS)
        assert inc is not None
        malicious_reasons = [r for r in inc["reasons"] if "malicious" in r.lower()]
        assert malicious_reasons, (
            f"Malware incident has no malicious-intel reason. Reasons: {inc['reasons']}"
        )


# ---------------------------------------------------------------------------
# Noise reduction stats test
# ---------------------------------------------------------------------------

class TestStats:
    def test_noise_reduction_pct_matches_independent_computation(
        self, pipeline_result, incidents, stats
    ):
        """
        noise_reduction_pct must equal the value computed independently here.
        (alerts not in any incident) / total_alerts * 100
        """
        # Reload raw alerts to compute independently
        import pipeline as p
        raw_alerts, _, _, _, _ = p.load_all()
        total = len(raw_alerts)
        incident_alert_ids: set = set()
        for inc in incidents:
            incident_alert_ids.update(inc["alert_ids"])
        noise_count = total - len(incident_alert_ids)
        expected_pct = round(noise_count / total * 100, 1)
        assert stats["noise_reduction_pct"] == expected_pct, (
            f"noise_reduction_pct mismatch: API says {stats['noise_reduction_pct']}, "
            f"independent computation says {expected_pct}"
        )

    def test_total_alerts_matches_data(self, stats):
        import pipeline as p
        raw_alerts, _, _, _, _ = p.load_all()
        assert stats["total_alerts"] == len(raw_alerts)
