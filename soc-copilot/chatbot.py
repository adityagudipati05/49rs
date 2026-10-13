"""
chatbot.py - Alert Diagnosis Chatbot for SOC Copilot.

Analyzes alerts (especially ungrouped / singleton alerts) to determine whether
they should be promoted to a new incident, merged into an existing incident,
or dismissed as noise.

Features:
- parse_alert_id(text): extracts and normalizes alert numbers (e.g. 'A-007', '007', 'alert 7', '#7').
  Unknown IDs return a friendly error listing the valid range.
- diagnose_alert(alert_id): deterministic diagnosis returning structured JSON.
- LLM layer (Groq primary, Anthropic optional, SHA-256 cache) with citations ending every sentence.
- Prompt injection protection via injection.py.
- Session management for follow-up questions.
"""
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Optional, Union

import actions as actions_module
import db as db_module
import injection as injection_module
import pipeline as pipeline_module
import validator as validator_module

CACHE_DIR = os.path.join(os.path.dirname(__file__), "cache", "chatbot")
os.makedirs(CACHE_DIR, exist_ok=True)

MODEL_NAME = "openai/gpt-oss-120b"

# In-memory session store: session_id -> {last_alert_id, last_diagnosis, history}
_SESSIONS: dict[str, dict] = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_payload(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Alert ID Extraction & Normalization
# ---------------------------------------------------------------------------

def parse_alert_id(text: str, all_alert_ids: Optional[list[str]] = None) -> str:
    """
    Robust extraction and normalization of alert number to repo format (A-xxx).
    Supports inputs such as 'A-007', '007', 'alert 7', '#7', 'A-7', 'alert #7', '40'.
    Unknown IDs return a friendly error listing the valid range.
    """
    if not text:
        return "Please provide an alert ID (e.g. A-007, 007, or #7)."

    clean_text = text.strip()

    # Pattern matches: A-007, A007, alert 7, #7, bare 007
    match = re.search(r"\bA[-_]?(\d+)\b", clean_text, re.IGNORECASE)
    if not match:
        match = re.search(r"#\s*(\d+)\b", clean_text)
    if not match:
        match = re.search(r"\balert\s*#?\s*(\d+)\b", clean_text, re.IGNORECASE)
    if not match:
        match = re.search(r"\b(\d{1,4})\b", clean_text)

    # Determine known alert IDs and valid range from real data
    if all_alert_ids is None:
        try:
            alerts, _, _, _, _ = pipeline_module.load_all()
            valid_set = {a["id"] for a in alerts}
        except Exception:
            valid_set = {f"A-{i:03d}" for i in range(1, 41)}
    else:
        valid_set = set(all_alert_ids)

    nums = sorted([int(aid[2:]) for aid in valid_set if aid.startswith("A-") and aid[2:].isdigit()])
    range_str = f"A-{nums[0]:03d} to A-{nums[-1]:03d}" if nums else "A-001 to A-040"

    if not match:
        return (
            f"Could not extract an alert ID from '{clean_text}'. "
            f"Please provide an alert number such as A-007, 007, or #7 (valid range: {range_str})."
        )

    num = int(match.group(1))
    candidate_id = f"A-{num:03d}"

    if candidate_id in valid_set:
        return candidate_id

    return (
        f"Unknown alert ID {candidate_id}. "
        f"Valid alerts currently in the system range from {range_str} ({len(valid_set)} alerts total)."
    )


def is_valid_alert_id(id_str: str) -> bool:
    """Return True if id_str is formatted like A-xxx and has no error text."""
    return bool(re.match(r"^A-\d{3,}$", id_str.strip()))


# ---------------------------------------------------------------------------
# Near-miss Correlation Analysis
# ---------------------------------------------------------------------------

def _find_near_misses(
    target_alert: dict,
    all_alerts: list[dict],
    incidents: list[dict],
) -> list[dict]:
    """
    Find other alerts that almost matched target_alert:
    - Shared user/host/resource/IP just outside the 2-hour window
    - Same source with similar event title
    - Alerts belonging to an existing incident that share an entity
    """
    near_misses: list[dict] = []
    target_id = target_alert["id"]

    try:
        ts_target = pipeline_module._parse_ts(target_alert["timestamp"])
    except Exception:
        ts_target = datetime.now(timezone.utc)

    # Pre-map alert IDs to incident IDs
    incident_map = {}
    for inc in incidents:
        for aid in inc.get("alert_ids", []):
            incident_map[aid] = inc["id"]

    for other in all_alerts:
        other_id = other["id"]
        if other_id == target_id:
            continue

        try:
            ts_other = pipeline_module._parse_ts(other["timestamp"])
            diff_hours = abs((ts_target - ts_other).total_seconds()) / 3600.0
        except Exception:
            diff_hours = 999.0

        shared_entities = []
        if target_alert.get("user") and target_alert.get("user") == other.get("user"):
            shared_entities.append(f"user '{target_alert['user']}'")
        if target_alert.get("host") and target_alert.get("host") == other.get("host"):
            shared_entities.append(f"host '{target_alert['host']}'")
        if target_alert.get("resource") and target_alert.get("resource") == other.get("resource"):
            shared_entities.append(f"resource '{target_alert['resource']}'")
        t_ip = target_alert.get("ip")
        if t_ip and not pipeline_module._is_private_ip(t_ip) and t_ip == other.get("ip"):
            shared_entities.append(f"IP '{t_ip}'")

        other_inc = incident_map.get(other_id)

        # Case 1: Shared entity but outside 2-hour window (or inside if ungrouped)
        if shared_entities:
            ent_desc = ", ".join(shared_entities)
            if other_inc:
                reason = (
                    f"Shares {ent_desc} with alert {other_id} in {other_inc} "
                    f"({diff_hours:.1f}h apart, outside 2h window)"
                    if diff_hours > 2.0
                    else f"Shares {ent_desc} with alert {other_id} in {other_inc} ({diff_hours:.1f}h apart)"
                )
            else:
                reason = (
                    f"Shares {ent_desc} with ungrouped alert {other_id} "
                    f"({diff_hours:.1f}h apart, outside 2h window)"
                    if diff_hours > 2.0
                    else f"Shares {ent_desc} with ungrouped alert {other_id} ({diff_hours:.1f}h apart)"
                )
            near_misses.append({
                "alert_id": other_id,
                "incident_id": other_inc,
                "reason": reason,
                "time_diff_hours": round(diff_hours, 1),
                "shared_entity": ent_desc,
            })
        # Case 2: Same source & similar title
        elif target_alert.get("source") == other.get("source") and target_alert.get("title") == other.get("title"):
            if diff_hours <= 12.0:
                near_misses.append({
                    "alert_id": other_id,
                    "incident_id": other_inc,
                    "reason": f"Same source '{target_alert.get('source')}' and title '{target_alert.get('title')}' ({diff_hours:.1f}h apart)",
                    "time_diff_hours": round(diff_hours, 1),
                    "shared_entity": target_alert.get("source"),
                })

    # Sort: shared entity first, then smaller time difference
    near_misses.sort(key=lambda m: (0 if "user" in m["reason"] or "IP" in m["reason"] or "host" in m["reason"] else 1, m["time_diff_hours"]))
    return near_misses[:5]


# ---------------------------------------------------------------------------
# Deterministic Diagnosis
# ---------------------------------------------------------------------------

def diagnose_alert(alert_id: str, db_path: Optional[str] = None) -> dict:
    """
    Produce a deterministic diagnosis of an alert returning structured JSON.
    Never invents data — missing lookups yield null.
    """
    alerts, assets, users, intel, playbooks = pipeline_module.load_all(db_path)
    pipeline_result = pipeline_module.build_pipeline(db_path)
    incidents = pipeline_result["incidents"]

    target_alert = next((a for a in alerts if a["id"] == alert_id), None)
    if not target_alert:
        raise ValueError(f"Alert {alert_id} not found in system data.")

    # Enrich target alert
    enriched = pipeline_module.enrich(target_alert, assets, users, intel)

    # 1. Grouping status
    incident_found = None
    for inc in incidents:
        if alert_id in inc.get("alert_ids", []):
            incident_found = inc["id"]
            break
    grouping_status = incident_found if incident_found else "ungrouped"

    # 2. Enrichment fields (null if missing, never invented)
    asset_obj = enriched.get("asset")
    asset_criticality = asset_obj.get("criticality") if asset_obj and isinstance(asset_obj, dict) else None

    user_obj = enriched.get("user_ctx")
    user_privilege = user_obj.get("privilege") if user_obj and isinstance(user_obj, dict) else None

    intel_obj = enriched.get("intel")
    threat_intel_verdict = intel_obj.get("verdict") if intel_obj and isinstance(intel_obj, dict) else None

    enrichment = {
        "asset_criticality": asset_criticality,
        "user_privilege": user_privilege,
        "threat_intel_verdict": threat_intel_verdict,
    }

    # 3. Plain-English summary
    summary = (
        f"Alert {alert_id} is a severity {target_alert.get('severity', 1)} {target_alert.get('source', 'unknown')} alert "
        f"recorded at {target_alert.get('timestamp', 'unknown')}. "
        f"Title: {target_alert.get('title', 'Untitled')}. "
        f"User: {target_alert.get('user') or 'None'}. "
        f"Host: {target_alert.get('host') or 'None'}. "
        f"IP: {target_alert.get('ip') or 'None'}."
    )

    # 4. Near-miss correlations
    near_misses = _find_near_misses(enriched, alerts, incidents)

    # 5. Risk score estimate (same formula as pipeline.py)
    sev = int(target_alert.get("severity", 1))
    risk_score = sev * 2
    breakdown = [f"Alert severity {sev} contributes {sev * 2} pts"]

    if asset_criticality is not None and asset_criticality >= 3:
        risk_score += 3
        breakdown.append(f"Critical asset involved (criticality={asset_criticality}) contributes +3 pts")

    if user_privilege is not None and user_privilege >= 3:
        risk_score += 3
        breakdown.append(f"High-privilege user involved (privilege={user_privilege}) contributes +3 pts")

    if threat_intel_verdict == "malicious":
        risk_score += 4
        breakdown.append("Malicious threat intel verdict for IP contributes +4 pts")
    elif threat_intel_verdict == "suspicious":
        risk_score += 2
        breakdown.append("Suspicious threat intel verdict for IP contributes +2 pts")

    # 6. Prompt injection findings via injection.py
    injection_findings = injection_module.detect_injection(target_alert)

    # 7. Incident recommendation
    reasons = []
    if grouping_status != "ungrouped":
        rec_action = f"merge into {grouping_status}"
        confidence = "high"
        reasons.append(f"Alert is already correlated into incident {grouping_status}")
    else:
        # Check if near-miss suggests merging into an existing incident
        incident_near_miss = next((nm for nm in near_misses if nm.get("incident_id")), None)
        if incident_near_miss:
            rec_action = f"merge into {incident_near_miss['incident_id']}"
            confidence = "high" if incident_near_miss["time_diff_hours"] <= 4.0 else "medium"
            reasons.append(incident_near_miss["reason"])
            if threat_intel_verdict in ("malicious", "suspicious"):
                reasons.append(f"Threat intel verdict is {threat_intel_verdict}")
        elif sev >= 3 or threat_intel_verdict in ("malicious", "suspicious") or (asset_criticality and asset_criticality >= 3):
            rec_action = "promote to new incident"
            confidence = "high" if (sev >= 4 or threat_intel_verdict == "malicious") else "medium"
            if sev >= 3:
                reasons.append(f"Elevated severity ({sev})")
            if threat_intel_verdict:
                reasons.append(f"Threat intel flagged IP as {threat_intel_verdict}")
            if asset_criticality and asset_criticality >= 3:
                reasons.append(f"High-criticality asset (level {asset_criticality})")
        else:
            rec_action = "likely noise / dismiss"
            confidence = "high"
            reasons.append("Low severity (1 or 2)")
            reasons.append("No malicious or suspicious threat intel on record")
            reasons.append("No correlation with active attack stories or existing incidents")

    # 8. Next steps (3 to 5 playbook-style actions using playbooks.json and actions.py)
    next_steps = []
    src = target_alert.get("source", "identity")
    pb_key = actions_module.SOURCE_TO_PLAYBOOK.get(src, "compromised_account")
    selected_playbook = playbooks.get(pb_key, {})
    steps_list = selected_playbook.get("steps", [])

    if rec_action == "likely noise / dismiss":
        next_steps = [
            {
                "step": 1,
                "action": "document_resolution",
                "description": f"Document analyst review notes for {alert_id} (Simulated: no real system changed)",
            },
            {
                "step": 2,
                "action": "tune_detection_rule",
                "description": f"Evaluate SIEM threshold rule for {target_alert.get('title')} to suppress recurrent noise (Simulated: no real system changed)",
            },
            {
                "step": 3,
                "action": "close_alert",
                "description": f"Close {alert_id} with resolution 'benign_noise' (Simulated: no real system changed)",
            },
        ]
    else:
        for s in steps_list[:4]:
            t_field = s.get("target_field")
            target_val = target_alert.get(t_field) or (enriched.get("user") if t_field == "user" else None) or "target-entity"
            next_steps.append({
                "step": len(next_steps) + 1,
                "action": s.get("action"),
                "description": f"Execute playbook step '{s.get('action')}' on {t_field} '{target_val}': {s.get('impact')} (Simulated: no real system changed)",
            })
        if len(next_steps) < 3:
            next_steps.append({
                "step": len(next_steps) + 1,
                "action": "notify_soc_team",
                "description": f"Notify duty analyst regarding {alert_id} triage decision (Simulated: no real system changed)",
            })

    return {
        "alert_id": alert_id,
        "summary": summary,
        "enrichment": enrichment,
        "grouping_status": grouping_status,
        "near_miss_correlations": near_misses,
        "incident_recommendation": rec_action,
        "recommendation_confidence": confidence,
        "recommendation_reasons": reasons,
        "risk_score_estimate": risk_score,
        "risk_score_breakdown": breakdown,
        "prompt_injection_findings": injection_findings,
        "next_steps": next_steps,
    }


# ---------------------------------------------------------------------------
# Conversational Explanation & LLM Layer
# ---------------------------------------------------------------------------

def generate_deterministic_explanation(alert_id: str, diagnosis: dict) -> str:
    """
    Generate a strictly valid deterministic explanation where EVERY sentence
    ends with [{alert_id}]. Guaranteed to pass validator.py.
    """
    rec = diagnosis["incident_recommendation"]
    conf = diagnosis["recommendation_confidence"]
    group_st = diagnosis["grouping_status"]
    score = diagnosis["risk_score_estimate"]
    intel = diagnosis["enrichment"]["threat_intel_verdict"] or "benign/none"

    sentences = [
        f"Alert {alert_id} was evaluated as part of automated SOC triage [{alert_id}].",
        f"Its current correlation state is {group_st} [{alert_id}].",
        f"Threat intel verdict for associated network traffic is {intel} [{alert_id}].",
        f"Estimated incident risk score for this alert is {score} points [{alert_id}].",
        f"The triage system recommends to {rec} with {conf} confidence [{alert_id}].",
    ]

    if diagnosis.get("prompt_injection_findings"):
        sentences.append(
            f"Security Notice: Prompt injection was identified in alert fields and neutralized from analysis [{alert_id}]."
        )

    return " ".join(sentences)


def _load_chat_cache(payload_hash: str) -> Optional[str]:
    path = os.path.join(CACHE_DIR, f"{payload_hash}.json")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("reply")
        except Exception:
            return None
    return None


def _save_chat_cache(payload_hash: str, reply: str) -> None:
    path = os.path.join(CACHE_DIR, f"{payload_hash}.json")
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "_meta": {
                    "model": MODEL_NAME,
                    "timestamp": _now_iso(),
                    "payload_hash": payload_hash,
                },
                "reply": reply,
            }, f, indent=2)
    except Exception:
        pass


def get_conversational_explanation(alert_id: str, diagnosis: dict, raw_alert: dict) -> tuple[str, bool]:
    """
    Produce a conversational explanation.
    Uses LLM (Groq/Anthropic) if API key is present and output passes validator.py.
    Falls back to deterministic explanation if no API key or invalid output.
    Returns (reply_text, citations_valid).
    """
    det_reply = generate_deterministic_explanation(alert_id, diagnosis)

    groq_api_key = os.environ.get("GROQ_API_KEY")
    anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY")

    if not groq_api_key and not anthropic_api_key:
        note = f"Note: LLM summary unavailable (no API key configured); deterministic diagnosis provided [{alert_id}]."
        full_reply = f"{det_reply} {note}"
        val = validator_module.validate(full_reply, [alert_id])
        return full_reply, val["passed"]

    # Sanitize alert so prompt injection payloads are never passed to the LLM
    clean_alert = injection_module.sanitize_alert_for_llm(raw_alert)

    prompt_payload = {
        "alert_id": alert_id,
        "clean_alert": {
            "source": clean_alert.get("source"),
            "severity": clean_alert.get("severity"),
            "timestamp": clean_alert.get("timestamp"),
            "title": clean_alert.get("title"),
            "description": clean_alert.get("description"),
            "user": clean_alert.get("user"),
            "host": clean_alert.get("host"),
            "ip": clean_alert.get("ip"),
        },
        "diagnosis": {
            "recommendation": diagnosis["incident_recommendation"],
            "confidence": diagnosis["recommendation_confidence"],
            "risk_score": diagnosis["risk_score_estimate"],
            "grouping_status": diagnosis["grouping_status"],
            "reasons": diagnosis["recommendation_reasons"],
        },
    }

    payload_hash = _hash_payload(prompt_payload)
    cached = _load_chat_cache(payload_hash)
    if cached:
        val = validator_module.validate(cached, [alert_id])
        if val["passed"]:
            return cached, True

    system_prompt = f"""You are an expert Security Operations Center (SOC) Copilot.
Explain the alert diagnosis to the security analyst concisely.

CRITICAL CITATION RULE:
Every single sentence in your explanation MUST end with the citation [{alert_id}]. No exceptions.
Respond with JSON only:
{{"explanation": "Sentence one [{alert_id}]. Sentence two [{alert_id}]."}}"""

    user_msg = json.dumps(prompt_payload, ensure_ascii=False)
    llm_text = None

    try:
        if anthropic_api_key:
            import anthropic
            client = anthropic.Anthropic(api_key=anthropic_api_key)
            resp = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=512,
                system=system_prompt,
                messages=[{"role": "user", "content": user_msg}],
            )
            raw = resp.content[0].text.strip()
            raw = re.sub(r"^```(?:json)?\s*", "", raw)
            raw = re.sub(r"\s*```$", "", raw).strip()
            parsed = json.loads(raw)
            llm_text = parsed.get("explanation")
        elif groq_api_key:
            from groq import Groq
            client = Groq(api_key=groq_api_key)
            resp = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_msg},
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
            )
            raw = resp.choices[0].message.content.strip()
            parsed = json.loads(raw)
            llm_text = parsed.get("explanation")
    except Exception:
        llm_text = None

    if llm_text:
        val = validator_module.validate(llm_text, [alert_id])
        if val["passed"]:
            _save_chat_cache(payload_hash, llm_text)
            return llm_text, True

    # Fall back to verified deterministic explanation
    full_reply = f"{det_reply} Note: LLM output fell back to deterministic diagnosis [{alert_id}]."
    val = validator_module.validate(full_reply, [alert_id])
    return full_reply, val["passed"]


# ---------------------------------------------------------------------------
# Chat Dispatcher (Commands & Sessions)
# ---------------------------------------------------------------------------

def process_chat_message(
    message: str,
    session_id: Optional[str] = None,
    analyst: str = "analyst-1",
    db_path: Optional[str] = None,
) -> dict:
    """
    Handle POST /chat command or lookup.
    Commands:
      - 'list' / 'list ungrouped': show ungrouped alerts
      - 'help': command usage
      - 'group': suggested groupings for ungrouped alerts
      - follow-up questions ('why?', 'what else is related?') referring to last alert discussed
      - alert ID (e.g. 'A-007', '007', 'alert 7', '#7')
    Logs lookups to audit log via db_module.append_audit.
    """
    sid = session_id or "default_session"
    session = _SESSIONS.setdefault(sid, {"last_alert_id": None, "last_diagnosis": None})

    text = message.strip()
    lower = text.lower()

    # 1. 'help' command
    if lower in ("help", "?", "commands"):
        reply = (
            "**SOC Copilot Alert Diagnosis Chatbot**\n\n"
            "I can diagnose any alert and determine if it belongs to an incident or is noise.\n\n"
            "**Supported commands:**\n"
            "- Enter an alert number (e.g. `A-007`, `007`, `alert 7`, `#7`) to run full diagnosis\n"
            "- `list` or `list ungrouped`: display all ungrouped alerts waiting for triage\n"
            "- `group`: view algorithmic suggestions for grouping unlinked alerts\n"
            "- Follow-up questions on the active alert: `why?`, `what else is related?`, `next steps?`"
        )
        return {"reply": reply, "diagnosis": None, "citations_valid": True}

    # 2. 'list' / 'list ungrouped' command
    if lower in ("list", "list ungrouped", "ungrouped", "show alerts"):
        ungrouped = pipeline_module.get_ungrouped_alerts(db_path)
        if not ungrouped:
            return {
                "reply": "No ungrouped alerts currently found in the system.",
                "diagnosis": None,
                "citations_valid": True,
            }
        lines = [f"Found **{len(ungrouped)} ungrouped alerts** in the queue:"]
        for a in ungrouped[:10]:
            lines.append(f"- **{a['id']}** (Sev {a.get('severity', 1)}): {a.get('title', 'Untitled')} [{a.get('source', '')}]")
        if len(ungrouped) > 10:
            lines.append(f"_...and {len(ungrouped) - 10} more. Type any alert ID to diagnose it._")
        return {
            "reply": "\n".join(lines),
            "diagnosis": None,
            "citations_valid": True,
        }

    # 3. 'group' command: suggested groupings of ungrouped alerts
    if lower in ("group", "suggest groupings", "group alerts"):
        ungrouped = pipeline_module.get_ungrouped_alerts(db_path)
        # Cluster by shared user, host, IP or title
        clusters: dict[str, list[str]] = {}
        for a in ungrouped:
            key = None
            if a.get("user") and not a["user"].startswith("noise."):
                key = f"user:{a['user']}"
            elif a.get("host") and not a["host"].startswith("AV-WS"):
                key = f"host:{a['host']}"
            elif a.get("ip") and not pipeline_module._is_private_ip(a["ip"]):
                key = f"ip:{a['ip']}"
            elif a.get("source") == "siem" and "Port Scan" in a.get("title", ""):
                key = "pattern:Internal Port Scans"
            elif a.get("source") == "edr" and "AV Detection" in a.get("title", ""):
                key = "pattern:Generic AV Detections (Adware)"

            if key:
                clusters.setdefault(key, []).append(a["id"])

        lines = ["**Suggested Groupings for Ungrouped Alerts:**\n"]
        for group_name, alert_ids in clusters.items():
            lines.append(f"- **{group_name}**: {', '.join(alert_ids)} ({len(alert_ids)} alerts)")
        if not clusters:
            lines.append("No entity-based groupings detected among ungrouped singletons.")

        return {
            "reply": "\n".join(lines),
            "diagnosis": None,
            "citations_valid": True,
        }

    # 4. Follow-up questions referring to last alert discussed
    last_aid = session.get("last_alert_id")
    last_diag = session.get("last_diagnosis")
    if last_aid and any(kw in lower for kw in ("why", "what else", "related", "next step", "steps", "explain")):
        if "why" in lower:
            reasons = "; ".join(last_diag["recommendation_reasons"])
            reply = (
                f"For {last_aid}, the recommendation is '{last_diag['incident_recommendation']}' [{last_aid}]. "
                f"The key reasons are: {reasons} [{last_aid}]."
            )
        elif "related" in lower:
            nms = last_diag.get("near_miss_correlations", [])
            if nms:
                rel_desc = ", ".join([f"{nm['alert_id']} ({nm['reason']})" for nm in nms[:3]])
                reply = f"Related alerts identified for {last_aid} include: {rel_desc} [{last_aid}]."
            else:
                reply = f"No closely correlated near-miss alerts were identified for {last_aid} [{last_aid}]."
        else:
            steps_desc = "; ".join([s["description"] for s in last_diag.get("next_steps", [])[:3]])
            reply = f"Suggested next response actions for {last_aid} are: {steps_desc} [{last_aid}]."

        val = validator_module.validate(reply, [last_aid])
        return {"reply": reply, "diagnosis": last_diag, "citations_valid": val["passed"]}

    # 5. Parse alert ID from message
    alerts, _, _, _, _ = pipeline_module.load_all(db_path)
    all_ids = [a["id"] for a in alerts]
    parsed_res = parse_alert_id(text, all_ids)

    # If parse_alert_id returned a non-ID (friendly error string)
    if not is_valid_alert_id(parsed_res):
        return {"reply": parsed_res, "diagnosis": None, "citations_valid": True}

    alert_id = parsed_res
    target_alert = next((a for a in alerts if a["id"] == alert_id), None)
    if not target_alert:
        return {
            "reply": f"Alert {alert_id} not found in repository data.",
            "diagnosis": None,
            "citations_valid": True,
        }

    # Run deterministic diagnosis
    diagnosis = diagnose_alert(alert_id, db_path)

    # Update session context
    session["last_alert_id"] = alert_id
    session["last_diagnosis"] = diagnosis

    # Log lookup in audit log as a real event
    try:
        db_module.append_audit(
            analyst=analyst,
            event="CHATBOT_LOOKUP",
            action_id=None,
            details={"alert_id": alert_id, "session_id": sid, "recommendation": diagnosis["incident_recommendation"]},
            db_path=db_path,
        )
    except Exception:
        pass

    # Conversational explanation
    reply_text, citations_valid = get_conversational_explanation(alert_id, diagnosis, target_alert)

    return {
        "reply": reply_text,
        "diagnosis": diagnosis,
        "citations_valid": citations_valid,
    }
