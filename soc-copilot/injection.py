"""
injection.py - Deterministic prompt-injection detection for SOC Copilot.

Scans alert title, description and raw fields for known injection patterns.
Works with NO API key — pure regex, no LLM.

Rules:
- Never changes risk scores.
- Findings are NEVER passed to the LLM as instructions.
- Missing fields are treated as empty string (null-safe).
"""
import re
from typing import Optional

# Case-insensitive patterns that indicate an attempt to hijack analyst or LLM behavior
_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r, re.IGNORECASE)
    for r in [
        r"ignore\s+(all\s+)?(previous|prior)\s+instructions",
        r"disregard\s+.*instructions",
        r"system\s+note",
        r"mark\s+(this\s+)?(incident\s+)?as\s+benign",
        r"you\s+are\s+now",
        r"new\s+system\s+prompt",
        r"end\s+of\s+system\s+prompt",
        r"act\s+as\s+if",
        r"pretend\s+(you\s+are|to\s+be)",
        r"forget\s+(all\s+)?previous",
        r"override\s+(all\s+)?instructions",
    ]
]

_FIELDS_TO_CHECK = ("title", "description", "raw")


def detect_injection(alerts: list[dict]) -> list[dict]:
    """
    Scan each alert's title, description and raw for injection patterns.

    Args:
        alerts: list of enriched alert dicts.

    Returns:
        List of findings, each:
          {"alert_id": str, "field": str, "matched": str}
        Empty list if no injections detected.
    """
    findings: list[dict] = []

    for alert in alerts:
        alert_id = alert.get("id", "unknown")
        for field in _FIELDS_TO_CHECK:
            text: Optional[str] = alert.get(field)
            if not text:
                continue
            for pattern in _INJECTION_PATTERNS:
                m = pattern.search(text)
                if m:
                    findings.append({
                        "alert_id": alert_id,
                        "field": field,
                        "matched": m.group(0),
                    })
                    break  # one finding per field per alert is enough

    return findings
