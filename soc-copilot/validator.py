"""
validator.py - Citation validator for LLM-generated summaries.

Validates that:
1. Every [A-xxx] citation in the summary refers to a real alert ID in the incident.
2. Every sentence in the summary ends with at least one citation.
3. Timeline source_ids reference real alert IDs.

Returns a structured dict — `passed` is computed from actual checks, never hardcoded.
"""
import re
from typing import Optional


# Regex to find citation markers like [A-001], [A-042], etc.
CITATION_PATTERN = re.compile(r"\[A-\d{3,}\]")

# Split sentences on . ! ? but not inside brackets
SENTENCE_SPLIT_PATTERN = re.compile(r"(?<=[.!?])\s+(?=[A-Z])")


def _extract_citations(text: str) -> list[str]:
    """Return all citation IDs found in text (e.g. ['A-001', 'A-007'])."""
    matches = CITATION_PATTERN.findall(text)
    return [m.strip("[]") for m in matches]


def _sentence_has_citation(sentence: str) -> bool:
    """Return True if the sentence ends with at least one citation before punctuation."""
    # A sentence is cited if a [A-xxx] appears near its end
    # Strip trailing whitespace, then check if the last non-space token is a citation
    stripped = sentence.rstrip()
    return bool(CITATION_PATTERN.search(stripped))


def _split_sentences(text: str) -> list[str]:
    """
    Split the summary into individual sentences.
    Handles multi-sentence text delimited by '. ', '! ', '? '.
    Returns only non-empty sentences.
    """
    # Replace newlines with spaces for uniform processing
    text = text.replace("\n", " ")
    # Split on sentence boundaries
    parts = re.split(r"(?<=[.!?])\s+", text)
    return [p.strip() for p in parts if p.strip()]


def validate(
    summary: str,
    incident_alert_ids: list[str],
    timeline: Optional[list[dict]] = None,
) -> dict:
    """
    Validate citations in a summary against the incident's alert IDs.

    Args:
        summary: The LLM-generated summary text.
        incident_alert_ids: List of valid alert IDs for this incident.
        timeline: Optional list of timeline entries with 'source_id' field.

    Returns:
        {
            citations_found: list of all [A-xxx] IDs found,
            valid_citations: IDs that match incident alerts,
            invalid_citations: IDs not in incident,
            uncited_sentences: sentences without a citation,
            timeline_invalid_ids: timeline source_ids not in incident,
            passed: bool (computed, not hardcoded),
        }
    """
    valid_ids_set = set(incident_alert_ids)

    citations_found = _extract_citations(summary)
    unique_citations = list(dict.fromkeys(citations_found))  # preserve order, dedupe

    valid_citations = [c for c in unique_citations if c in valid_ids_set]
    invalid_citations = [c for c in unique_citations if c not in valid_ids_set]

    sentences = _split_sentences(summary)
    uncited_sentences = [s for s in sentences if not _sentence_has_citation(s)]

    # Validate timeline source_ids
    timeline_invalid_ids: list[str] = []
    if timeline:
        for entry in timeline:
            sid = entry.get("source_id")
            if sid and sid not in valid_ids_set:
                timeline_invalid_ids.append(sid)

    # `passed` is computed from real checks — NEVER hardcoded
    passed = (
        len(invalid_citations) == 0
        and len(uncited_sentences) == 0
        and len(unique_citations) >= 1
        and len(timeline_invalid_ids) == 0
    )

    return {
        "citations_found": unique_citations,
        "valid_citations": valid_citations,
        "invalid_citations": invalid_citations,
        "uncited_sentences": uncited_sentences,
        "timeline_invalid_ids": timeline_invalid_ids,
        "passed": passed,
    }
