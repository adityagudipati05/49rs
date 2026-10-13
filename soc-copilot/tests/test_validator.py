"""
tests/test_validator.py - Tests for the citation validator.
"""
import pytest
from validator import validate


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_IDS = ["A-001", "A-002", "A-003", "A-004", "A-005"]

# A clean summary where every sentence is cited with valid IDs
CLEAN_SUMMARY = (
    "User priya.sharma performed impossible travel between two countries within minutes [A-001]. "
    "Shortly after, the MFA method was changed from TOTP to SMS from the same IP [A-002]. "
    "A mailbox forwarding rule was created redirecting all email to an external address [A-003]. "
    "The account then logged in from a previously unseen device [A-004]. "
    "Finally, a massive email export of 4,821 messages was observed far above baseline [A-005]."
)

# Summary with an invalid citation (A-999 doesn't exist in incident)
INVALID_CITATION_SUMMARY = (
    "User priya.sharma performed impossible travel [A-001]. "
    "A non-existent alert was referenced here [A-999]."
)

# Summary with an uncited sentence
UNCITED_SENTENCE_SUMMARY = (
    "User priya.sharma performed impossible travel [A-001]. "
    "This sentence has no citation at all."
)

# Summary with both invalid citation and uncited sentence
BOTH_PROBLEMS_SUMMARY = (
    "Referenced a bad alert ID here [A-999]. "
    "This sentence has no citation whatsoever."
)


# ---------------------------------------------------------------------------
# Clean summary passes
# ---------------------------------------------------------------------------

class TestValidatorPasses:
    def test_clean_summary_passes(self):
        result = validate(CLEAN_SUMMARY, VALID_IDS)
        assert result["passed"] is True
        assert result["invalid_citations"] == []
        assert result["uncited_sentences"] == []
        assert len(result["valid_citations"]) >= 1

    def test_clean_summary_citations_all_valid(self):
        result = validate(CLEAN_SUMMARY, VALID_IDS)
        for cid in result["citations_found"]:
            assert cid in VALID_IDS

    def test_clean_summary_no_uncited_sentences(self):
        result = validate(CLEAN_SUMMARY, VALID_IDS)
        assert result["uncited_sentences"] == []


# ---------------------------------------------------------------------------
# Invalid citation caught
# ---------------------------------------------------------------------------

class TestInvalidCitation:
    def test_invalid_id_is_caught(self):
        result = validate(INVALID_CITATION_SUMMARY, VALID_IDS)
        assert "A-999" in result["invalid_citations"]

    def test_passed_is_false_with_invalid_citation(self):
        result = validate(INVALID_CITATION_SUMMARY, VALID_IDS)
        assert result["passed"] is False

    def test_valid_citation_still_recognized(self):
        result = validate(INVALID_CITATION_SUMMARY, VALID_IDS)
        assert "A-001" in result["valid_citations"]


# ---------------------------------------------------------------------------
# Uncited sentence caught
# ---------------------------------------------------------------------------

class TestUncitedSentence:
    def test_uncited_sentence_is_caught(self):
        result = validate(UNCITED_SENTENCE_SUMMARY, VALID_IDS)
        assert len(result["uncited_sentences"]) >= 1

    def test_passed_is_false_with_uncited_sentence(self):
        result = validate(UNCITED_SENTENCE_SUMMARY, VALID_IDS)
        assert result["passed"] is False


# ---------------------------------------------------------------------------
# Both problems
# ---------------------------------------------------------------------------

class TestBothProblems:
    def test_both_invalid_citation_and_uncited_sentence(self):
        result = validate(BOTH_PROBLEMS_SUMMARY, VALID_IDS)
        assert result["passed"] is False
        assert "A-999" in result["invalid_citations"]
        assert len(result["uncited_sentences"]) >= 1


# ---------------------------------------------------------------------------
# Empty summary
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_summary_fails(self):
        result = validate("", VALID_IDS)
        assert result["passed"] is False
        assert result["citations_found"] == []

    def test_no_citations_fails(self):
        result = validate("This is a summary with no citations at all.", VALID_IDS)
        assert result["passed"] is False

    def test_timeline_invalid_id_caught(self):
        timeline = [
            {"time": "2024-01-01T00:00:00Z", "event": "test", "source_id": "A-999", "attack_stage": "recon"}
        ]
        result = validate(CLEAN_SUMMARY, VALID_IDS, timeline=timeline)
        assert "A-999" in result["timeline_invalid_ids"]
        assert result["passed"] is False

    def test_timeline_valid_ids_pass(self):
        timeline = [
            {"time": "2024-01-01T00:00:00Z", "event": "test", "source_id": "A-001", "attack_stage": "recon"}
        ]
        result = validate(CLEAN_SUMMARY, VALID_IDS, timeline=timeline)
        assert result["timeline_invalid_ids"] == []


# ---------------------------------------------------------------------------
# Citations after period (Task 2)
# ---------------------------------------------------------------------------

class TestCitationAfterPeriod:
    def test_citations_after_period_both_cited_passes(self):
        text = "Spawned PowerShell. [A-006] Then it beaconed out. [A-008]"
        res = validate(text, ["A-006", "A-008"])
        assert res["passed"] is True

    def test_citations_before_period_both_cited_passes(self):
        text = "Spawned PowerShell [A-006]. Then it beaconed out [A-008]."
        res = validate(text, ["A-006", "A-008"])
        assert res["passed"] is True

    def test_second_sentence_uncited_fails(self):
        text = "Spawned PowerShell. [A-006] Then it beaconed out."
        res = validate(text, ["A-006", "A-008"])
        assert res["passed"] is False
        assert res["uncited_sentences"] == ["Then it beaconed out."]

    def test_invalid_citation_after_period_fails(self):
        text = "Spawned PowerShell. [A-099]"
        res = validate(text, ["A-006"])
        assert res["passed"] is False
        assert res["invalid_citations"] == ["A-099"]

