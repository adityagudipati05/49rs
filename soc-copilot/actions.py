"""
actions.py - Playbook selection and action card construction.

Rules decide playbook selection. LLM only explains the reasoning.
Targets are resolved from actual incident entities — no defaults invented.
Warnings are only generated when real data supports them.
"""
from typing import Optional


# ---------------------------------------------------------------------------
# Playbook selection (rule-based)
# ---------------------------------------------------------------------------

SOURCE_TO_PLAYBOOK = {
    "identity": "compromised_account",
    "edr": "malware_host",
    "cloud": "cloud_exposure",
}

# Priority order when multiple sources present
SOURCE_PRIORITY = ["edr", "identity", "cloud", "siem"]


def pick_playbook(incident: dict) -> Optional[str]:
    """
    Select a playbook by rule from alert sources.
    Priority: edr > identity > cloud > siem.
    Returns a playbook name or None if no matching source.
    """
    sources = set(incident.get("sources", []))
    for src in SOURCE_PRIORITY:
        if src in sources and src in SOURCE_TO_PLAYBOOK:
            return SOURCE_TO_PLAYBOOK[src]
    return None


# ---------------------------------------------------------------------------
# Action card construction
# ---------------------------------------------------------------------------

def _resolve_target(step: dict, incident: dict) -> Optional[str]:
    """
    Resolve the target value for a step from incident entities.
    Returns the first matching entity or None.
    """
    target_field = step.get("target_field")
    entities = incident.get("entities", {})

    if target_field == "user":
        users = entities.get("users", [])
        return users[0] if users else None
    elif target_field == "host":
        hosts = entities.get("hosts", [])
        return hosts[0] if hosts else None
    elif target_field == "ip":
        ips = entities.get("ips", [])
        return ips[0] if ips else None
    elif target_field == "resource":
        resources = entities.get("resources", [])
        return resources[0] if resources else None

    return None


def _generate_warnings(step: dict, incident: dict, assets: dict) -> list[str]:
    """
    Generate warnings only when real data supports them.
    E.g., warn if target host is a production system.
    """
    warnings: list[str] = []
    target_field = step.get("target_field")
    entities = incident.get("entities", {})

    if target_field in ("host", "resource"):
        hosts = entities.get("hosts", [])
        for host in hosts:
            asset_info = assets.get(host)
            if asset_info and asset_info.get("env") == "production":
                crit = asset_info.get("criticality")
                warnings.append(
                    f"Target '{host}' is a production system"
                    + (f" (criticality={crit})" if crit is not None else "")
                    + ". Confirm before proceeding."
                )

    if target_field == "user":
        for alert in incident.get("alerts", []):
            user_ctx = alert.get("user_ctx")
            if user_ctx and user_ctx.get("privilege", 0) >= 3:
                priv = user_ctx["privilege"]
                user = alert.get("user")
                warnings.append(
                    f"User '{user}' has elevated privilege (level={priv}). "
                    "Disabling may impact business-critical operations."
                )
                break  # one warning per field type is enough

    return warnings


def build_actions(
    incident: dict,
    playbook_name: str,
    playbooks: dict,
    db_get_action_status,  # callable(action_id) -> dict | None
    assets: dict,
) -> list[dict]:
    """
    Build one action card per playbook step.
    Status is read from the DB — never assumed.
    Warnings are only added if real data supports them.

    Args:
        incident: The scored incident dict.
        playbook_name: Name of the selected playbook.
        playbooks: Full playbook dict from data.
        db_get_action_status: Callable that takes action_id and returns DB row or None.
        assets: Assets dict for warning resolution.

    Returns:
        List of action card dicts.
    """
    playbook = playbooks.get(playbook_name)
    if not playbook:
        return []

    inc_id = incident["id"]
    cards: list[dict] = []

    for step in playbook.get("steps", []):
        step_id = step["id"]
        action_id = f"{inc_id}-{step_id}"

        # Resolve target from real incident entities
        target = _resolve_target(step, incident)

        # Status comes from DB with anchor validation — default is pending
        db_row = db_get_action_status(action_id)
        current_anchor = incident.get("anchor")
        invalidation_reason = None

        if not db_row:
            status = "pending"
        else:
            stored_anchor = db_row.get("incident_anchor")
            if stored_anchor is None:
                # NULL-anchor legacy rows: treat as pending
                status = "pending"
                invalidation_reason = "legacy approval (no anchor stored)"
            elif stored_anchor != current_anchor:
                # Stored anchor does not match current anchor
                status = "pending"
                invalidation_reason = "approval no longer matches incident (alerts changed)"
            else:
                status = db_row.get("decision", "pending")

        # Warnings only if real data supports them
        warnings = _generate_warnings(step, incident, assets)

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
