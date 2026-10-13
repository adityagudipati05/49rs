"""
api.py - FastAPI backend for SOC Copilot.

Endpoints:
  GET  /incidents           - ranked incident list + summary stats
  GET  /incidents/{id}      - full incident detail
  POST /actions/{id}/decision - approve or reject an action
  POST /actions/{id}/execute  - execute (simulated) if approved, 403 otherwise
  GET  /audit               - audit log newest first
"""
import json
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

import actions as actions_module
import db
import llm as llm_module
import pipeline as pipeline_module
import validator as validator_module

@asynccontextmanager
async def lifespan(app):
    db.init_db()
    yield


app = FastAPI(title="SOC Copilot API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Pipeline cache (reloaded on each startup; data files rarely change)
# ---------------------------------------------------------------------------

_pipeline_cache: Optional[dict] = None


def _get_pipeline() -> dict:
    global _pipeline_cache
    if _pipeline_cache is None:
        _pipeline_cache = pipeline_module.build_pipeline()
    return _pipeline_cache


def _get_incident_by_id(inc_id: str) -> Optional[dict]:
    result = _get_pipeline()
    for inc in result["incidents"]:
        if inc["id"] == inc_id:
            return inc
    return None


def _get_assets() -> dict:
    """Load assets for action card generation."""
    from pipeline import load_json
    try:
        return load_json("assets.json").get("assets", {})
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

ALLOWED_DECISIONS = {"approved", "rejected"}


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


# ---------------------------------------------------------------------------
# GET /incidents
# ---------------------------------------------------------------------------

@app.get("/incidents")
def list_incidents() -> dict:
    result = _get_pipeline()
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

    return {
        "incidents": incident_list,
        "stats": stats,
    }


# ---------------------------------------------------------------------------
# GET /incidents/{inc_id}
# ---------------------------------------------------------------------------

@app.get("/incidents/{inc_id}")
def get_incident(inc_id: str) -> dict:
    inc = _get_incident_by_id(inc_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {inc_id} not found")

    # Load summary from cache only — don't block on LLM call
    summary = llm_module.load_cached_summary(inc_id)

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

    # Build action cards with live DB status
    action_cards = actions_module.build_actions(
        incident=inc,
        playbook_name=playbook_name,
        playbooks=playbooks,
        db_get_action_status=db.get_approval,
        assets=assets,
    )

    # Context cards: user, asset, threat intel (None shown as-is, not invented)
    context = _build_context(inc)

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
        "alerts": [
            {
                "id": a["id"],
                "timestamp": a["timestamp"],
                "source": a["source"],
                "severity": a["severity"],
                "title": a["title"],
                "description": a["description"],
                "raw": a["raw"],
                "user": a.get("user"),
                "host": a.get("host"),
                "ip": a.get("ip"),
            }
            for a in inc["alerts"]
        ],
        "summary": summary,
        "validation": validation,
        "context": context,
        "playbook": playbook_name,
        "action_cards": action_cards,
    }


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
# POST /actions/{action_id}/decision
# ---------------------------------------------------------------------------

@app.post("/actions/{action_id}/decision")
def post_decision(action_id: str, body: DecisionRequest) -> dict:
    # Write to DB
    db.upsert_approval(
        action_id=action_id,
        decision=body.decision,
        analyst=body.analyst,
        comment=body.comment,
        evidence_ids=None,
    )

    # Append to audit log
    db.append_audit(
        analyst=body.analyst,
        event=f"DECISION_{body.decision.upper()}",
        action_id=action_id,
        details={"comment": body.comment, "decision": body.decision},
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
    Backend enforces: approved record must exist, or HTTP 403 is returned.
    Label: "Simulated: no real system changed"
    """
    is_approved, approval_row = db.require_approved(action_id)

    if not is_approved:
        # Log blocked attempt
        db.append_audit(
            analyst=analyst,
            event="EXECUTION_BLOCKED",
            action_id=action_id,
            details={
                "reason": "No approved record found",
                "decision_on_record": (approval_row or {}).get("decision"),
                "label": "Simulated: no real system changed",
            },
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Execution blocked: action has not been approved.",
                "action_id": action_id,
                "label": "Simulated: no real system changed",
            },
        )

    # Log simulated execution
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
    summary = llm_module.get_summary(inc, rule_based_playbook=playbook_name)
    return {"inc_id": inc_id, "summary": summary}
