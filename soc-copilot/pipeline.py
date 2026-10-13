"""
pipeline.py - Load, enrich, correlate, score, and build incidents.

Changes in Phase 2:
  - load_all() now merges seeded alerts (origin="seeded") with manual alerts
    from the DB (origin="manual"). alerts.json is never written.
  - build_pipeline() is wrapped in a module-level cache that is invalidated
    by calling invalidate_pipeline_cache(). Callers (api.py) call invalidate
    after inserting or deleting manual alerts.
"""
import json
import os
from datetime import datetime, timezone
from typing import Any, Optional

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

# Module-level in-process cache.  None means "dirty, rebuild on next call".
_PIPELINE_CACHE: Optional[dict] = None


def invalidate_pipeline_cache() -> None:
    """Mark the pipeline cache as dirty. Thread-safe for CPython (GIL protects assignment)."""
    global _PIPELINE_CACHE
    _PIPELINE_CACHE = None


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_json(filename: str) -> dict:
    path = os.path.join(DATA_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_all(db_path: Optional[str] = None) -> tuple[list[dict], dict, dict, dict, dict]:
    """
    Return (alerts, assets, users, intel, playbooks).

    alerts = seeded (from alerts.json, origin="seeded") +
             manual  (from DB manual_alerts table, origin="manual").
    alerts.json is NEVER written by this function or any caller.
    """
    import db as db_module

    alerts_data = load_json("alerts.json")
    assets_data = load_json("assets.json")
    users_data = load_json("users.json")
    intel_data = load_json("threat_intel.json")
    playbooks_data = load_json("playbooks.json")

    seeded_alerts = alerts_data["alerts"]
    # Tag seeded alerts without mutating the JSON-loaded originals
    tagged_seeded = [dict(a, origin="seeded") for a in seeded_alerts]

    # Merge manual alerts (already stored as full dicts in DB)
    manual_rows = db_module.get_manual_alerts(db_path)
    manual_alerts = [dict(a, origin="manual") for a in manual_rows]

    all_alerts = tagged_seeded + manual_alerts

    return (
        all_alerts,
        assets_data["assets"],
        users_data["users"],
        intel_data["intel"],
        playbooks_data["playbooks"],
    )


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------

def enrich(alert: dict, assets: dict, users: dict, intel: dict) -> dict:
    """
    Attach asset, user_ctx, and intel to an alert dict.
    Missing lookups yield None — never crash.
    `raw` is never modified.
    """
    enriched = dict(alert)

    # Asset lookup — use host field (which may be a resource like s3://...)
    host_key = alert.get("host")
    enriched["asset"] = assets.get(host_key) if host_key else None

    # User context lookup
    user_key = alert.get("user")
    enriched["user_ctx"] = users.get(user_key) if user_key else None

    # Threat intel lookup on ip
    ip_key = alert.get("ip")
    enriched["intel"] = intel.get(ip_key) if ip_key else None

    return enriched


# ---------------------------------------------------------------------------
# Correlation via union-find
# ---------------------------------------------------------------------------

PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "192.168.", "127.")

TWO_HOURS_SECONDS = 2 * 3600


def _is_private_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)


def _parse_ts(ts_str: str) -> datetime:
    return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))


def _within_window(ts_a: datetime, ts_b: datetime) -> bool:
    return abs((ts_a - ts_b).total_seconds()) <= TWO_HOURS_SECONDS


class UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))
        self.rank = [0] * n

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, x: int, y: int) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self.rank[rx] < self.rank[ry]:
            rx, ry = ry, rx
        self.parent[ry] = rx
        if self.rank[rx] == self.rank[ry]:
            self.rank[rx] += 1


def correlate(enriched_alerts: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Link alerts sharing user/host/ip/resource within a 2-hour window.
    Groups of >=2 become incidents (INC-1, INC-2, ...).
    Singletons go to unlinked list.
    Returns (incidents, unlinked).
    """
    n = len(enriched_alerts)
    uf = UnionFind(n)
    timestamps = [_parse_ts(a["timestamp"]) for a in enriched_alerts]

    for i in range(n):
        for j in range(i + 1, n):
            if not _within_window(timestamps[i], timestamps[j]):
                continue

            a, b = enriched_alerts[i], enriched_alerts[j]

            # Correlation keys: user, host (including resource), ip (non-private)
            def keys(alert: dict) -> set:
                k: set = set()
                if alert.get("user"):
                    k.add(("user", alert["user"]))
                if alert.get("host"):
                    k.add(("host", alert["host"]))
                if alert.get("resource"):
                    k.add(("resource", alert["resource"]))
                ip = alert.get("ip")
                if ip and not _is_private_ip(ip):
                    k.add(("ip", ip))
                return k

            if keys(a) & keys(b):
                uf.union(i, j)

    # Group by root
    groups: dict[int, list[int]] = {}
    for i in range(n):
        root = uf.find(i)
        groups.setdefault(root, []).append(i)

    incidents: list[dict] = []
    unlinked: list[dict] = []
    inc_num = 1

    # Sort groups for deterministic ordering by earliest alert timestamp
    sorted_roots = sorted(
        groups.items(),
        key=lambda kv: min(timestamps[i] for i in kv[1]),
    )

    for root, indices in sorted_roots:
        group_alerts = [enriched_alerts[i] for i in sorted(indices, key=lambda i: timestamps[i])]
        if len(group_alerts) >= 2:
            incident = _build_incident(f"INC-{inc_num}", group_alerts)
            incidents.append(incident)
            inc_num += 1
        else:
            unlinked.append(group_alerts[0])

    return incidents, unlinked


def _build_incident(inc_id: str, alerts: list[dict]) -> dict:
    """Build an incident dict from a list of correlated enriched alerts."""
    users = sorted({a["user"] for a in alerts if a.get("user")})
    hosts = sorted({a["host"] for a in alerts if a.get("host")})
    ips = sorted({a["ip"] for a in alerts if a.get("ip") and not _is_private_ip(a.get("ip", ""))})
    resources = sorted({a.get("resource") for a in alerts if a.get("resource")})
    sources = sorted({a["source"] for a in alerts})

    # anchor = earliest alert ID in the group — used for stable approval tracking
    anchor = alerts[0]["id"]

    return {
        "id": inc_id,
        "alert_ids": [a["id"] for a in alerts],
        "alerts": alerts,
        "entities": {
            "users": users,
            "hosts": hosts,
            "ips": ips,
            "resources": resources,
        },
        "sources": sources,
        "earliest": alerts[0]["timestamp"],
        "latest": alerts[-1]["timestamp"],
        "anchor": anchor,  # earliest alert ID; stable across rescoring
    }


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def score_incident(incident: dict) -> tuple[int, str, list[str]]:
    """
    Returns (score, label, reasons).
    Score components:
      - highest_severity * 2
      - +3 if any asset criticality >= 3
      - +3 if any user privilege >= 3
      - +4 if any intel verdict == "malicious"
      - +number of distinct sources (if >= 2)
    Labels: >=14 Critical, >=10 High, >=6 Medium, else Low
    All reason strings are derived from actual values.
    """
    score = 0
    reasons: list[str] = []
    alerts = incident["alerts"]

    # Highest severity
    severities = [a["severity"] for a in alerts]
    max_sev = max(severities)
    sev_contribution = max_sev * 2
    score += sev_contribution
    reasons.append(f"Highest alert severity: {max_sev} (contributes {sev_contribution} pts)")

    # Asset criticality
    asset_crits = [
        a["asset"]["criticality"]
        for a in alerts
        if a.get("asset") and a["asset"].get("criticality") is not None
    ]
    if asset_crits:
        max_crit = max(asset_crits)
        if max_crit >= 3:
            score += 3
            reasons.append(f"Critical asset involved (criticality={max_crit})")

    # User privilege
    user_privs = [
        a["user_ctx"]["privilege"]
        for a in alerts
        if a.get("user_ctx") and a["user_ctx"].get("privilege") is not None
    ]
    if user_privs:
        max_priv = max(user_privs)
        if max_priv >= 3:
            score += 3
            reasons.append(f"High-privilege user involved (privilege={max_priv})")

    # Malicious intel
    malicious_ips = [
        a["ip"]
        for a in alerts
        if a.get("intel") and a["intel"].get("verdict") == "malicious" and a.get("ip")
    ]
    if malicious_ips:
        score += 4
        reasons.append(f"Malicious threat intel for IP(s): {', '.join(sorted(set(malicious_ips)))}")

    # Distinct sources
    distinct_sources = incident["sources"]
    n_sources = len(distinct_sources)
    if n_sources >= 2:
        score += n_sources
        reasons.append(f"{n_sources} distinct alert sources: {', '.join(distinct_sources)}")

    # Label
    if score >= 14:
        label = "Critical"
    elif score >= 10:
        label = "High"
    elif score >= 6:
        label = "Medium"
    else:
        label = "Low"

    return score, label, reasons


# ---------------------------------------------------------------------------
# Per-alert triage classification & summary stats
# ---------------------------------------------------------------------------

def classify_unlinked(alert: dict) -> str:
    """
    Classify an unlinked alert as 'needs_review' or 'low_priority'.
    needs_review if severity >= 3 OR alert["intel"] verdict is 'malicious' or 'suspicious'.
    Otherwise low_priority. Missing intel is not suspicious.
    """
    sev = alert.get("severity")
    if sev is not None:
        try:
            if int(sev) >= 3:
                return "needs_review"
        except (ValueError, TypeError):
            pass

    intel = alert.get("intel")
    if isinstance(intel, dict) and intel.get("verdict") in ("malicious", "suspicious"):
        return "needs_review"

    return "low_priority"


def compute_stats(
    all_alerts: list[dict],
    incidents: list[dict],
    unlinked: list[dict],
) -> dict:
    """
    Compute summary stats from actual results. No hardcoding.
    noise_reduction_pct = fraction of alerts classified as low_priority.
    """
    total_alerts = len(all_alerts)
    incident_count = len(incidents)
    # All alert IDs in incidents
    incident_alert_ids: set[str] = set()
    for inc in incidents:
        incident_alert_ids.update(inc["alert_ids"])
    unlinked_count = len(unlinked)

    needs_review_count = sum(1 for a in unlinked if classify_unlinked(a) == "needs_review")
    low_priority_count = sum(1 for a in unlinked if classify_unlinked(a) == "low_priority")

    # noise_reduction_pct must count ONLY low_priority alerts as noise
    noise_alerts_count = low_priority_count
    noise_reduction_pct = (low_priority_count / total_alerts * 100) if total_alerts > 0 else 0.0

    return {
        "total_alerts": total_alerts,
        "incident_count": incident_count,
        "unlinked_count": unlinked_count,
        "alerts_in_incidents": len(incident_alert_ids),
        "noise_alerts_count": noise_alerts_count,
        "noise_reduction_pct": round(noise_reduction_pct, 1),
        "needs_review_count": needs_review_count,
        "low_priority_count": low_priority_count,
    }


# ---------------------------------------------------------------------------
# Main entry point — build everything
# ---------------------------------------------------------------------------

def build_pipeline(db_path: Optional[str] = None) -> dict:
    """
    Run the full pipeline and return a dict with incidents, unlinked, stats.
    Incidents sorted by score descending.

    When called with db_path=None (production), uses the module-level cache.
    Tests pass db_path explicitly and bypass the cache.
    """
    global _PIPELINE_CACHE

    # Cache only applies to the production code-path (db_path=None)
    if db_path is None and _PIPELINE_CACHE is not None:
        return _PIPELINE_CACHE

    alerts, assets, users, intel, playbooks = load_all(db_path)

    enriched = [enrich(a, assets, users, intel) for a in alerts]
    incidents, unlinked = correlate(enriched)

    scored_incidents = []
    for inc in incidents:
        score, label, reasons = score_incident(inc)
        inc["score"] = score
        inc["label"] = label
        inc["reasons"] = reasons
        scored_incidents.append(inc)

    scored_incidents.sort(key=lambda x: x["score"], reverse=True)

    for inc in scored_incidents:
        for a in inc["alerts"]:
            a["incident_id"] = inc["id"]
            a["triage"] = "in_incident"

    for a in unlinked:
        a["incident_id"] = None
        a["triage"] = classify_unlinked(a)

    stats = compute_stats(alerts, scored_incidents, unlinked)

    result = {
        "incidents": scored_incidents,
        "unlinked": unlinked,
        "stats": stats,
        "playbooks": playbooks,
    }

    if db_path is None:
        _PIPELINE_CACHE = result

    return result


def get_ungrouped_alerts(db_path: Optional[str] = None) -> list[dict]:
    """
    Return all ungrouped alerts (alerts not in any correlated incident).
    Computed dynamically from pipeline execution with no hardcoded lists.
    """
    result = build_pipeline(db_path)
    return result.get("unlinked", [])


if __name__ == "__main__":
    result = build_pipeline()
    print(f"\nStats: {result['stats']}")
    for inc in result["incidents"]:
        print(f"  {inc['id']} score={inc['score']} label={inc['label']} alerts={inc['alert_ids']}")
    print(f"  Unlinked: {len(result['unlinked'])} alerts")
