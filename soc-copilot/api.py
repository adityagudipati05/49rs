"""
api.py - FastAPI backend for SOC Copilot.

Endpoints:
  GET  /incidents              - ranked incident list + summary stats
  GET  /incidents/{id}         - full incident detail (includes summary_stale)
  POST /incidents/{id}/summary - trigger LLM summary
  POST /actions/{id}/decision  - approve or reject (validates action belongs to incident)
  POST /actions/{id}/execute   - execute (simulated); checks anchor stability
  GET  /audit                  - audit log newest first
  POST /alerts                 - add a manual alert, rebuild pipeline
  GET  /alerts                 - list all alerts (seeded + manual)
  DELETE /alerts/{id}          - remove a manual alert
"""
import ipaddress
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator, model_validator

import actions as actions_module
import chatbot as chatbot_module
import db
import injection as injection_module
import llm as llm_module
import pipeline as pipeline_module
import validator as validator_module


@asynccontextmanager
async def lifespan(app):
    db.init_db()
    yield


app = FastAPI(title="SOC Copilot API", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Pipeline cache — invalidated on alert add/remove
# ---------------------------------------------------------------------------

_pipeline_cache: Optional[dict] = None


def _get_pipeline() -> dict:
    global _pipeline_cache
    if _pipeline_cache is None:
        _pipeline_cache = pipeline_module.build_pipeline()
    return _pipeline_cache


def _invalidate_pipeline() -> None:
    """Invalidate both the api-level cache and the pipeline module cache."""
    global _pipeline_cache
    _pipeline_cache = None
    pipeline_module.invalidate_pipeline_cache()


def _get_incident_by_id(inc_id: str) -> Optional[dict]:
    result = _get_pipeline()
    for inc in result["incidents"]:
        if inc["id"] == inc_id:
            return inc
    return None


def _get_assets() -> dict:
    """Load assets for action card generation."""
    try:
        return pipeline_module.load_json("assets.json").get("assets", {})
    except Exception:
        return {}


def _incident_list_payload(result: dict) -> dict:
    """Serialize the incident list + stats for GET /incidents and POST /alerts response."""
    incidents = result["incidents"]
    stats = result["stats"]
    incident_list = []
    for inc in incidents:
        incident_list.append({
            "id": inc["id"],
            "score": inc["score"],
            "label": inc["label"],
            "reasons": inc["reasons"],
            "alert_count": len(inc["alert_ids"]),
            "alert_ids": inc["alert_ids"],
            "entities": inc["entities"],
            "sources": inc["sources"],
            "earliest": inc["earliest"],
            "latest": inc["latest"],
            "top_reason": inc["reasons"][0] if inc["reasons"] else None,
        })
    return {"incidents": incident_list, "stats": stats}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

ALLOWED_DECISIONS = {"approved", "rejected"}
ALLOWED_SOURCES = {"siem", "edr", "identity", "cloud"}


class DecisionRequest(BaseModel):
    decision: str
    analyst: str
    comment: Optional[str] = None

    @field_validator("decision")
    @classmethod
    def decision_must_be_valid(cls, v: str) -> str:
        if v not in ALLOWED_DECISIONS:
            raise ValueError(f"decision must be one of {ALLOWED_DECISIONS}")
        return v

    @field_validator("analyst")
    @classmethod
    def analyst_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("analyst must not be empty")
        return v.strip()


def _empty_to_none(v: Optional[str]) -> Optional[str]:
    if v is None or v.strip() == "":
        return None
    return v.strip()


class AlertRequest(BaseModel):
    source: str
    severity: int
    timestamp: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    ip: Optional[str] = None
    resource: Optional[str] = None
    title: str
    description: Optional[str] = None
    raw: Optional[str] = None
    analyst: str

    @field_validator("source")
    @classmethod
    def source_must_be_valid(cls, v: str) -> str:
        if v not in ALLOWED_SOURCES:
            raise ValueError(f"source must be one of {sorted(ALLOWED_SOURCES)}")
        return v

    @field_validator("severity")
    @classmethod
    def severity_must_be_1_to_4(cls, v: int) -> int:
        if v not in (1, 2, 3, 4):
            raise ValueError("severity must be an integer 1-4")
        return v

    @field_validator("title")
    @classmethod
    def title_required_and_max(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("title is required")
        if len(v) > 200:
            raise ValueError("title must be at most 200 characters")
        return v

    @field_validator("description")
    @classmethod
    def description_max(cls, v: Optional[str]) -> Optional[str]:
        v = _empty_to_none(v)
        if v and len(v) > 2000:
            raise ValueError("description must be at most 2000 characters")
        return v

    @field_validator("raw")
    @classmethod
    def raw_max(cls, v: Optional[str]) -> Optional[str]:
        v = _empty_to_none(v)
        if v and len(v) > 4000:
            raise ValueError("raw must be at most 4000 characters")
        return v

    @field_validator("user", "host", "resource")
    @classmethod
    def entity_max(cls, v: Optional[str]) -> Optional[str]:
        v = _empty_to_none(v)
        if v and len(v) > 200:
            raise ValueError("field must be at most 200 characters")
        return v

    @field_validator("ip")
    @classmethod
    def ip_valid(cls, v: Optional[str]) -> Optional[str]:
        v = _empty_to_none(v)
        if v is None:
            return None
        if len(v) > 200:
            raise ValueError("ip must be at most 200 characters")
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"ip '{v}' is not a valid IPv4 or IPv6 address")
        return v

    @field_validator("analyst")
    @classmethod
    def analyst_required(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("analyst is required and must not be empty")
        return v

    @field_validator("timestamp")
    @classmethod
    def timestamp_valid(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v.strip() == "":
            return None
        v = v.strip()
        # Validate ISO 8601 by parsing
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"timestamp '{v}' is not valid ISO 8601")
        return v

    @model_validator(mode="after")
    def at_least_one_entity(self) -> "AlertRequest":
        if not any([self.user, self.host, self.ip, self.resource]):
            raise ValueError(
                "at least one of user, host, ip, resource must be provided "
                "for the alert to be correlatable"
            )
        return self


# ---------------------------------------------------------------------------
# GET /incidents
# ---------------------------------------------------------------------------

@app.get("/incidents")
def list_incidents() -> dict:
    return _incident_list_payload(_get_pipeline())


# ---------------------------------------------------------------------------
# GET /incidents/{inc_id}
# ---------------------------------------------------------------------------

@app.get("/incidents/{inc_id}")
def get_incident(inc_id: str) -> dict:
    inc = _get_incident_by_id(inc_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {inc_id} not found")

    # Load summary — pass incident for stale-detection
    summary = llm_module.load_cached_summary(inc_id, incident=inc)

    # Validation result
    validation = None
    if summary and summary.get("status") != "unavailable":
        summary_text = summary.get("summary", "")
        timeline = summary.get("timeline", [])
        validation = validator_module.validate(
            summary_text,
            inc["alert_ids"],
            timeline,
        )

    # Pick playbook (rule-based)
    playbook_name = actions_module.pick_playbook(inc)
    playbooks = _get_pipeline()["playbooks"]
    assets = _get_assets()

    # Build action cards with live DB status, passing anchor for validity check
    action_cards = _build_action_cards_with_anchor(inc, playbook_name, playbooks, assets)

    # Context cards
    context = _build_context(inc)

    # Deterministic injection detection — never alters score, never passed to LLM
    injection_findings = injection_module.detect_injection(inc.get("alerts", []))

    # Basic timeline from alert timestamps — available even without LLM
    timeline_basic = _build_timeline_basic(inc)

    serialized_alerts = [
        {
            "id": a["id"],
            "timestamp": a["timestamp"],
            "source": a["source"],
            "severity": a["severity"],
            "title": a["title"],
            "description": a["description"],
            "raw": a.get("raw"),
            "user": a.get("user"),
            "host": a.get("host"),
            "ip": a.get("ip"),
            "origin": a.get("origin", "seeded"),
        }
        for a in inc["alerts"]
    ]

    return {
        "id": inc["id"],
        "score": inc["score"],
        "label": inc["label"],
        "reasons": inc["reasons"],
        "alert_ids": inc["alert_ids"],
        "entities": inc["entities"],
        "sources": inc["sources"],
        "earliest": inc["earliest"],
        "latest": inc["latest"],
        "anchor": inc.get("anchor"),
        "alerts": serialized_alerts,
        "summary": summary,
        "validation": validation,
        "context": context,
        "playbook": playbook_name,
        "action_cards": action_cards,
        "injection_findings": injection_findings,
        "timeline_basic": timeline_basic,
    }


def _build_action_cards_with_anchor(
    inc: dict,
    playbook_name: Optional[str],
    playbooks: dict,
    assets: dict,
) -> list[dict]:
    """
    Build action cards, checking anchor stability for each.
    If a stored approval's anchor doesn't match current, status is shown as
    'pending' with an approval_invalidated_reason.
    """
    current_anchor = inc.get("anchor")

    def _get_status_with_anchor(action_id: str) -> tuple[str, Optional[str]]:
        row = db.get_approval(action_id)
        if not row:
            return "pending", None
        decision = row.get("decision", "pending")
        stored_anchor = row.get("incident_anchor")
        # Legacy NULL anchor — treat as pending
        if stored_anchor is None:
            return "pending", "legacy approval (no anchor stored)"
        if stored_anchor != current_anchor:
            return "pending", "approval no longer matches incident (alerts changed)"
        return decision, None

    playbook = playbooks.get(playbook_name) if playbook_name else None
    if not playbook:
        return []

    inc_id = inc["id"]
    cards: list[dict] = []

    for step in playbook.get("steps", []):
        step_id = step["id"]
        action_id = f"{inc_id}-{step_id}"

        target = actions_module._resolve_target(step, inc)
        status, invalidation_reason = _get_status_with_anchor(action_id)
        warnings = actions_module._generate_warnings(step, inc, assets)

        card = {
            "action_id": action_id,
            "step_id": step_id,
            "action": step["action"],
            "target_field": step.get("target_field"),
            "target": target,
            "impact": step["impact"],
            "risk": step["risk"],
            "status": status,
            "warnings": warnings,
            "playbook": playbook_name,
        }
        if invalidation_reason:
            card["approval_invalidated_reason"] = invalidation_reason

        cards.append(card)

    return cards


def _build_timeline_basic(inc: dict) -> list[dict]:
    """
    Build a deterministic timeline from alert timestamps.
    Sorted ascending. attack_stage is always null — never invented.
    """
    alerts = sorted(
        inc.get("alerts", []),
        key=lambda a: a.get("timestamp") or "",
    )
    return [
        {
            "time": a.get("timestamp"),
            "event": a.get("title"),
            "source_id": a.get("id"),
            "source": a.get("source"),
            "attack_stage": None,
        }
        for a in alerts
    ]


def _build_context(inc: dict) -> dict:
    """
    Build context cards from enriched incident data.
    None values are preserved — never invented.
    """
    alerts = inc.get("alerts", [])

    user_ctx = None
    for a in alerts:
        if a.get("user_ctx"):
            user_ctx = {"user": a.get("user"), **a["user_ctx"]}
            break

    asset_ctx = None
    for a in alerts:
        if a.get("asset"):
            asset_ctx = {"host": a.get("host"), **a["asset"]}
            break

    intel_ctx = None
    for a in alerts:
        if a.get("intel"):
            intel_ctx = {"ip": a.get("ip"), **a["intel"]}
            break

    return {
        "user": user_ctx,
        "asset": asset_ctx,
        "threat_intel": intel_ctx,
    }


# ---------------------------------------------------------------------------
# POST /incidents/{inc_id}/summary  (trigger LLM call)
# ---------------------------------------------------------------------------

@app.post("/incidents/{inc_id}/summary")
def trigger_summary(inc_id: str) -> dict:
    """
    Trigger an LLM summary generation for an incident.
    This may block briefly. Cache is populated on completion.
    """
    inc = _get_incident_by_id(inc_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {inc_id} not found")

    playbook_name = actions_module.pick_playbook(inc)
    summary = llm_module.get_summary(inc, rule_based_playbook=playbook_name, force_refresh=True)
    # After regeneration, summary is fresh — not stale
    summary = dict(summary)
    summary["summary_stale"] = False
    return {"inc_id": inc_id, "summary": summary}


# ---------------------------------------------------------------------------
# GET /incidents/{inc_id}/case-note
# ---------------------------------------------------------------------------

@app.get("/incidents/{inc_id}/case-note")
def get_case_note(inc_id: str) -> dict:
    """
    Generate a structured markdown case note for the incident.
    Headings always appear in the same fixed order.
    Never invents text for missing sections.
    """
    inc = _get_incident_by_id(inc_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {inc_id} not found")

    summary = llm_module.load_cached_summary(inc_id, incident=inc)
    summary_available = summary and summary.get("status") != "unavailable"

    playbook_name = actions_module.pick_playbook(inc)
    playbooks = _get_pipeline()["playbooks"]
    assets = _get_assets()
    action_cards = _build_action_cards_with_anchor(inc, playbook_name, playbooks, assets)
    context = _build_context(inc)
    timeline_basic = _build_timeline_basic(inc)
    injection_findings = injection_module.detect_injection(inc.get("alerts", []))

    validation = None
    if summary_available:
        validation = validator_module.validate(
            summary.get("summary", ""),
            inc["alert_ids"],
            summary.get("timeline", []),
        )

    lines: list[str] = []

    # # Title
    title = (summary.get("title") if summary_available else None) or inc_id
    lines.append(f"# {title}\n")

    # ## Risk
    lines.append("## Risk\n")
    lines.append(f"**Score:** {inc['score']}  **Label:** {inc['label']}\n")
    if inc.get("reasons"):
        lines.append("**Scoring factors:**")
        for r in inc["reasons"]:
            lines.append(f"- {r}")
    lines.append("")

    # ## Summary
    lines.append("## Summary\n")
    if summary_available and summary.get("summary"):
        lines.append(summary["summary"])
    else:
        lines.append("AI summary unavailable.")
    lines.append("")

    # ## Timeline
    lines.append("## Timeline\n")
    if summary_available and summary.get("timeline"):
        timeline = summary["timeline"]
        lines.append("| Time | Event | Source | Stage |")
        lines.append("|------|-------|--------|-------|")
        for e in timeline:
            t = e.get("time") or "—"
            ev = e.get("event") or "—"
            src = e.get("source_id") or "—"
            stg = e.get("attack_stage") or "—"
            lines.append(f"| {t} | {ev} | {src} | {stg} |")
    else:
        lines.append("*Built from alert timestamps (not AI)*\n")
        lines.append("| Time | Event | Source |")
        lines.append("|------|-------|--------|")
        for e in timeline_basic:
            t = e.get("time") or "—"
            ev = e.get("event") or "—"
            src = e.get("source_id") or "—"
            lines.append(f"| {t} | {ev} | {src} |")
    lines.append("")

    # ## Context
    lines.append("## Context\n")
    entities = inc.get("entities", {})
    if entities.get("users"):
        lines.append(f"**Users:** {', '.join(entities['users'])}")
    if entities.get("hosts"):
        lines.append(f"**Hosts:** {', '.join(entities['hosts'])}")
    if entities.get("ips"):
        lines.append(f"**IPs:** {', '.join(entities['ips'])}")
    if context.get("threat_intel"):
        ti = context["threat_intel"]
        lines.append(f"**Threat intel ({ti.get('ip')}):** verdict={ti.get('verdict')}, confidence={ti.get('confidence')}")
    lines.append("")

    # ## Recommended playbook
    lines.append("## Recommended playbook\n")
    if playbook_name:
        lines.append(f"**{playbook_name.replace('_', ' ').title()}**")
        if summary_available and summary.get("playbook_reasoning"):
            lines.append(f"AI reasoning: {summary['playbook_reasoning']}")
    else:
        lines.append("No playbook matched.")
    lines.append("")

    # ## Actions and decisions
    lines.append("## Actions and decisions\n")
    if action_cards:
        for card in action_cards:
            lines.append(f"**{card['action_id']}** — {card.get('action', '').replace('_', ' ').title()}")
            lines.append(f"- Target: {card.get('target') or 'unknown'}")
            lines.append(f"- Status: {card.get('status', 'pending')}")
            row = db.get_approval(card["action_id"])
            if row and row.get("decision"):
                lines.append(f"- Analyst: {row.get('analyst')}")
                if row.get("comment"):
                    lines.append(f"- Comment: {row['comment']}")
            lines.append("")
    else:
        lines.append("No action cards generated.")
    lines.append("")

    # ## Unknowns and injection findings
    lines.append("## Unknowns and injection findings\n")
    unknowns = (summary.get("unknowns") or []) if summary_available else []
    if unknowns:
        lines.append("**Unknowns:**")
        for u in unknowns:
            lines.append(f"- {u}")
    if injection_findings:
        lines.append("**Injection findings:**")
        for f in injection_findings:
            lines.append(f"- Alert {f['alert_id']} ({f['field']}): `{f['matched']}`")
    if not unknowns and not injection_findings:
        lines.append("None.")
    lines.append("")

    # ## Validation
    lines.append("## Validation\n")
    if validation:
        status = "✅ Passed" if validation.get("passed") else "❌ Failed"
        lines.append(f"**Status:** {status}")
        if validation.get("invalid_citations"):
            lines.append(f"- Invalid citations: {', '.join(validation['invalid_citations'])}")
        if validation.get("uncited_sentences"):
            lines.append(f"- Uncited sentences: {len(validation['uncited_sentences'])}")
        if validation.get("timeline_invalid_ids"):
            lines.append(f"- Timeline invalid IDs: {', '.join(validation['timeline_invalid_ids'])}")
    else:
        lines.append("No AI summary to validate.")
    lines.append("")

    # Footer
    lines.append("---")
    lines.append("*Synthetic data. Execution is simulated.*")

    markdown = "\n".join(lines)
    return {"markdown": markdown}




# ---------------------------------------------------------------------------
# POST /actions/{action_id}/decision
# ---------------------------------------------------------------------------

@app.post("/actions/{action_id}/decision")
def post_decision(action_id: str, body: DecisionRequest) -> dict:
    """
    Record an approve/reject decision.
    Validates that action_id belongs to a current incident — 404 if not.
    Stores the incident anchor for stable approval tracking.
    """
    # Find which incident owns this action_id
    result = _get_pipeline()
    owning_incident = None
    for inc in result["incidents"]:
        inc_id = inc["id"]
        playbook_name = actions_module.pick_playbook(inc)
        if playbook_name:
            playbooks = result["playbooks"]
            playbook = playbooks.get(playbook_name)
            if playbook:
                for step in playbook.get("steps", []):
                    if f"{inc_id}-{step['id']}" == action_id:
                        owning_incident = inc
                        break
        if owning_incident:
            break

    if owning_incident is None:
        raise HTTPException(
            status_code=404,
            detail=f"Action {action_id} does not belong to any current incident",
        )

    anchor = owning_incident.get("anchor")

    # Write to DB with anchor
    db.upsert_approval(
        action_id=action_id,
        decision=body.decision,
        analyst=body.analyst,
        comment=body.comment,
        evidence_ids=None,
        incident_anchor=anchor,
    )

    # Append to audit log
    db.append_audit(
        analyst=body.analyst,
        event=f"DECISION_{body.decision.upper()}",
        action_id=action_id,
        details={"comment": body.comment, "decision": body.decision, "anchor": anchor},
    )

    return {
        "action_id": action_id,
        "decision": body.decision,
        "analyst": body.analyst,
        "status": "recorded",
    }


# ---------------------------------------------------------------------------
# POST /actions/{action_id}/execute
# ---------------------------------------------------------------------------

@app.post("/actions/{action_id}/execute")
def execute_action(action_id: str, analyst: str = "unknown") -> dict:
    """
    Execute is simulated only.
    Backend enforces: approved record with matching anchor must exist, or HTTP 403.
    Label: "Simulated: no real system changed"
    """
    # Find current incident anchor for this action
    result = _get_pipeline()
    current_anchor = None
    action_found = False
    for inc in result["incidents"]:
        inc_id = inc["id"]
        playbook_name = actions_module.pick_playbook(inc)
        if playbook_name:
            playbooks = result["playbooks"]
            playbook = playbooks.get(playbook_name)
            if playbook:
                for step in playbook.get("steps", []):
                    if f"{inc_id}-{step['id']}" == action_id:
                        current_anchor = inc.get("anchor")
                        action_found = True
                        break
        if action_found:
            break

    if not action_found:
        raise HTTPException(
            status_code=404,
            detail=f"Action {action_id} does not belong to any current incident",
        )

    is_approved, approval_row, reason = db.require_approved_with_anchor(
        action_id, current_anchor
    )

    if not is_approved:
        block_detail = reason if reason else "No approved record found"
        db.append_audit(
            analyst=analyst,
            event="EXECUTION_BLOCKED",
            action_id=action_id,
            details={
                "reason": block_detail,
                "decision_on_record": (approval_row or {}).get("decision"),
                "label": "Simulated: no real system changed",
            },
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": f"Execution blocked: {block_detail}",
                "action_id": action_id,
                "label": "Simulated: no real system changed",
            },
        )

    db.append_audit(
        analyst=analyst,
        event="EXECUTED_SIMULATED",
        action_id=action_id,
        details={
            "approved_by": approval_row.get("analyst"),
            "label": "Simulated: no real system changed",
        },
    )

    return {
        "status": "executed (simulated)",
        "action_id": action_id,
        "label": "Simulated: no real system changed",
        "approved_by": approval_row.get("analyst"),
    }


# ---------------------------------------------------------------------------
# GET /audit
# ---------------------------------------------------------------------------

@app.get("/audit")
def get_audit(limit: int = 200) -> dict:
    rows = db.get_audit_log(limit=limit)
    return {"audit_log": rows}


# ---------------------------------------------------------------------------
# POST /alerts  — add a manual alert
# ---------------------------------------------------------------------------

@app.post("/alerts")
def add_alert(body: AlertRequest) -> dict:
    """
    Add a new manual alert.
    Server assigns the ID (next free A-NNN across seeded + manual).
    Invalidates the pipeline cache and returns the freshly rebuilt incident list + stats.
    """
    # Gather seeded IDs for next_id computation
    seeded = pipeline_module.load_json("alerts.json")["alerts"]
    seeded_ids = [a["id"] for a in seeded]
    alert_id = db.next_alert_id(seeded_ids)

    # Use real UTC now when timestamp omitted
    ts = body.timestamp
    if ts is None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    alert_payload = {
        "id": alert_id,
        "timestamp": ts,
        "source": body.source,
        "severity": body.severity,
        "title": body.title,
        "description": body.description,
        "raw": body.raw,
        "user": body.user,
        "host": body.host,
        "ip": body.ip,
        "resource": body.resource,
        "origin": "manual",
    }

    db.insert_manual_alert(alert_id, alert_payload, body.analyst)

    db.append_audit(
        analyst=body.analyst,
        event="ALERT_ADDED",
        action_id=None,
        details={"alert_id": alert_id, "analyst": body.analyst},
    )

    # Invalidate and rebuild
    _invalidate_pipeline()
    result = _get_pipeline()

    return {
        "alert": alert_payload,
        **_incident_list_payload(result),
    }


# ---------------------------------------------------------------------------
# GET /alerts
# ---------------------------------------------------------------------------

@app.get("/alerts")
def list_alerts(
    origin: Optional[str] = Query(default=None),
    triage: Optional[str] = Query(default=None),
) -> dict:
    """
    Return all alerts (seeded + manual) with origin, incident_id, and triage fields, newest first.
    Optional ?origin=manual or ?origin=seeded filter.
    Optional ?triage=in_incident|needs_review|low_priority filter.
    """
    result = _get_pipeline()
    # Map each alert ID that is part of an incident to its incident ID
    alert_incident_map: dict[str, str] = {}
    for inc in result["incidents"]:
        for a in inc["alerts"]:
            alert_incident_map[a["id"]] = inc["id"]

    # Collect alerts from all incidents + unlinked
    all_alerts: list[dict] = []
    seen: set[str] = set()
    for inc in result["incidents"]:
        for a in inc["alerts"]:
            if a["id"] not in seen:
                all_alerts.append(a)
                seen.add(a["id"])
    for a in result.get("unlinked", []):
        if a["id"] not in seen:
            all_alerts.append(a)
            seen.add(a["id"])

    # Sort newest first by timestamp
    all_alerts.sort(key=lambda a: a.get("timestamp", ""), reverse=True)

    # Filter by origin if requested
    if origin in ("manual", "seeded"):
        all_alerts = [a for a in all_alerts if a.get("origin") == origin]

    alerts_out = []
    for a in all_alerts:
        aid = a["id"]
        if aid in alert_incident_map:
            inc_id = alert_incident_map[aid]
            triage_val = "in_incident"
        else:
            inc_id = None
            triage_val = pipeline_module.classify_unlinked(a)

        if triage and triage_val != triage:
            continue

        alerts_out.append({
            "id": a["id"],
            "timestamp": a["timestamp"],
            "source": a["source"],
            "severity": a["severity"],
            "title": a["title"],
            "description": a.get("description"),
            "user": a.get("user"),
            "host": a.get("host"),
            "ip": a.get("ip"),
            "resource": a.get("resource"),
            "origin": a.get("origin", "seeded"),
            "incident_id": inc_id,
            "triage": triage_val,
        })

    return {"alerts": alerts_out}


# ---------------------------------------------------------------------------
# DELETE /alerts/{alert_id}
# ---------------------------------------------------------------------------

@app.delete("/alerts/{alert_id}")
def delete_alert(alert_id: str, analyst: str = Query(...)) -> dict:
    """
    Remove a manual alert.
    403 if the alert is seeded. 404 if not found at all.
    """
    if not analyst or not analyst.strip():
        raise HTTPException(status_code=422, detail="analyst query param is required")

    # Check if it exists among seeded alerts
    seeded = pipeline_module.load_json("alerts.json")["alerts"]
    seeded_ids = {a["id"] for a in seeded}
    if alert_id in seeded_ids:
        raise HTTPException(
            status_code=403,
            detail=f"Alert {alert_id} is seeded (synthetic) and cannot be removed",
        )

    deleted = db.delete_manual_alert(alert_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    db.append_audit(
        analyst=analyst.strip(),
        event="ALERT_REMOVED",
        action_id=None,
        details={"alert_id": alert_id, "analyst": analyst.strip()},
    )

    _invalidate_pipeline()
    result = _get_pipeline()

    return {
        "deleted": alert_id,
        **_incident_list_payload(result),
    }


# ---------------------------------------------------------------------------
# Chatbot & Ungrouped Alerts
# ---------------------------------------------------------------------------

class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None
    analyst: Optional[str] = "analyst-1"

    @field_validator("message")
    @classmethod
    def message_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("message must not be empty")
        return v.strip()


@app.get("/alerts/ungrouped")
def list_ungrouped_alerts() -> dict:
    """
    List of ungrouped alerts (alerts not in any correlated incident).
    Computed dynamically from real data with no hardcoded lists.
    """
    ungrouped = pipeline_module.get_ungrouped_alerts()
    return {
        "ungrouped_alerts": [
            {
                "id": a["id"],
                "severity": a.get("severity", 1),
                "title": a.get("title", ""),
                "source": a.get("source", ""),
                "timestamp": a.get("timestamp"),
                "user": a.get("user"),
                "host": a.get("host"),
                "ip": a.get("ip"),
                "triage": a.get("triage", "low_priority"),
            }
            for a in ungrouped
        ],
        "count": len(ungrouped),
    }


@app.post("/chat")
def chat_endpoint(body: ChatRequest) -> dict:
    """
    Chatbot endpoint for diagnosing alerts, follow-up Q&A, and commands (list, help, group).
    """
    analyst_name = (body.analyst or "analyst-1").strip()
    return chatbot_module.process_chat_message(
        message=body.message,
        session_id=body.session_id,
        analyst=analyst_name,
    )
