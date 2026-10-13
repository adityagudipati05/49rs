"""
app.py - Streamlit UI for SOC Copilot.

Three views:
1. Incident Queue - banner stats, sorted incidents with colored badges
2. Incident Detail - score, AI summary, citations, timeline, context, actions
3. Audit Log - from /audit endpoint

All values displayed come from the API — nothing is hardcoded in the UI.
Footer shows "Demo data is synthetic".
"""
import time
from typing import Optional

import requests
import streamlit as st

API_BASE = "http://localhost:8000"

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="SOC AI Copilot",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS
# ---------------------------------------------------------------------------
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

  html, body, [class*="css"] {
    font-family: 'Inter', sans-serif !important;
    background-color: #0d1117 !important;
    color: #e6edf3 !important;
  }

  .main .block-container {
    padding-top: 1.5rem;
    padding-bottom: 2rem;
  }

  /* Cards */
  .soc-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 1.1rem 1.3rem;
    margin-bottom: 1rem;
    transition: border-color 0.2s ease;
  }
  .soc-card:hover { border-color: #58a6ff; }

  /* Badges */
  .badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.04em;
  }
  .badge-critical { background: #ff000030; color: #ff6b6b; border: 1px solid #ff6b6b50; }
  .badge-high     { background: #ff8c0030; color: #ffa657; border: 1px solid #ffa65750; }
  .badge-medium   { background: #ffcc0030; color: #e3b341; border: 1px solid #e3b34150; }
  .badge-low      { background: #2ea04330; color: #56d364; border: 1px solid #56d36450; }

  /* Stat banner */
  .stat-box {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1rem 1.4rem;
    text-align: center;
  }
  .stat-number { font-size: 2rem; font-weight: 700; color: #58a6ff; }
  .stat-label  { font-size: 0.75rem; color: #8b949e; margin-top: 2px; }

  /* Validation badges */
  .val-pass { background: #23863630; border: 1px solid #2ea04380; color: #56d364; padding: 4px 12px; border-radius: 6px; font-size: 13px; font-weight: 600; }
  .val-fail { background: #ff8c0020; border: 1px solid #ffa65780; color: #ffa657; padding: 4px 12px; border-radius: 6px; font-size: 13px; font-weight: 600; }

  /* Timeline table */
  .timeline-row { padding: 6px 0; border-bottom: 1px solid #21262d; font-size: 13px; }

  /* Sidebar */
  [data-testid="stSidebar"] {
    background: #0d1117 !important;
    border-right: 1px solid #21262d;
  }

  /* Footer */
  .footer {
    margin-top: 3rem;
    padding: 1.5rem 0;
    border-top: 1px solid #21262d;
    font-size: 12px;
    color: #8b949e;
  }

  /* Severity dots */
  .sev-1 { color: #56d364; }
  .sev-2 { color: #e3b341; }
  .sev-3 { color: #ffa657; }
  .sev-4 { color: #ff6b6b; }

  h1, h2, h3 { color: #e6edf3 !important; }
  .stButton>button {
    background: #21262d;
    border: 1px solid #30363d;
    color: #e6edf3;
    border-radius: 6px;
    font-size: 13px;
    padding: 6px 16px;
  }
  .stButton>button:hover { border-color: #58a6ff; color: #58a6ff; }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def api_get(path: str) -> Optional[dict]:
    try:
        r = requests.get(f"{API_BASE}{path}", timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"API error ({path}): {e}")
        return None


def api_post(path: str, payload: dict = None, params: dict = None) -> Optional[dict]:
    try:
        r = requests.post(f"{API_BASE}{path}", json=payload, params=params, timeout=15)
        return r
    except Exception as e:
        st.error(f"API error (POST {path}): {e}")
        return None


def badge_html(label: str) -> str:
    cls = f"badge-{label.lower()}"
    return f'<span class="badge {cls}">{label}</span>'


def sev_label(sev: int) -> str:
    mapping = {1: "🟢 Low", 2: "🟡 Medium", 3: "🟠 High", 4: "🔴 Critical"}
    return mapping.get(sev, str(sev))


# ---------------------------------------------------------------------------
# Sidebar navigation
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("## 🛡️ SOC AI Copilot")
    st.markdown("---")
    view = st.radio(
        "Navigate",
        ["🚨 Incident Queue", "📋 Incident Detail", "📜 Audit Log"],
        label_visibility="collapsed",
    )

    if view == "📋 Incident Detail":
        incidents_data = api_get("/incidents")
        if incidents_data:
            inc_ids = [i["id"] for i in incidents_data.get("incidents", [])]
            selected_id = st.selectbox("Select Incident", inc_ids)
            st.session_state["selected_incident"] = selected_id

    st.markdown("---")
    st.markdown(
        "<div style='font-size:11px;color:#8b949e;'>API: localhost:8000</div>",
        unsafe_allow_html=True,
    )


# ============================================================
# VIEW 1: INCIDENT QUEUE
# ============================================================
if view == "🚨 Incident Queue":
    st.markdown("# 🚨 Incident Queue")
    data = api_get("/incidents")

    if data:
        stats = data["stats"]
        incidents = data["incidents"]

        # Stat banner — all computed values from API
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown(f"""
            <div class="stat-box">
              <div class="stat-number">{stats['total_alerts']}</div>
              <div class="stat-label">Total Alerts</div>
            </div>""", unsafe_allow_html=True)
        with c2:
            st.markdown(f"""
            <div class="stat-box">
              <div class="stat-number">{stats['incident_count']}</div>
              <div class="stat-label">Incidents</div>
            </div>""", unsafe_allow_html=True)
        with c3:
            st.markdown(f"""
            <div class="stat-box">
              <div class="stat-number">{stats['noise_reduction_pct']}%</div>
              <div class="stat-label">Noise Reduction</div>
            </div>""", unsafe_allow_html=True)
        with c4:
            st.markdown(f"""
            <div class="stat-box">
              <div class="stat-number">{stats['unlinked_count']}</div>
              <div class="stat-label">Unlinked Alerts</div>
            </div>""", unsafe_allow_html=True)

        st.markdown("---")

        if not incidents:
            st.info("No incidents found.")
        else:
            for inc in incidents:  # already sorted by score desc
                entities = inc["entities"]
                users_str = ", ".join(entities.get("users", [])) or "—"
                hosts_str = ", ".join(entities.get("hosts", [])) or "—"
                ips_str = ", ".join(entities.get("ips", [])) or "—"

                with st.container():
                    col_badge, col_info, col_btn = st.columns([1, 6, 1])
                    with col_badge:
                        st.markdown(badge_html(inc["label"]), unsafe_allow_html=True)
                        st.markdown(f"**Score: {inc['score']}**")

                    with col_info:
                        st.markdown(f"### {inc['id']}")
                        st.markdown(
                            f"**Alerts:** {inc['alert_count']} &nbsp;|&nbsp; "
                            f"**Sources:** {', '.join(inc['sources'])}",
                            unsafe_allow_html=True,
                        )
                        st.markdown(
                            f"👤 `{users_str}` &nbsp; 🖥️ `{hosts_str}` &nbsp; 🌐 `{ips_str}`",
                            unsafe_allow_html=True,
                        )
                        if inc.get("top_reason"):
                            st.caption(f"🏷️ {inc['top_reason']}")

                    with col_btn:
                        if st.button("Open →", key=f"open_{inc['id']}"):
                            st.session_state["selected_incident"] = inc["id"]
                            st.rerun()

                st.markdown("---")


# ============================================================
# VIEW 2: INCIDENT DETAIL
# ============================================================
elif view == "📋 Incident Detail":
    inc_id = st.session_state.get("selected_incident")
    if not inc_id:
        st.info("Select an incident from the sidebar.")
        st.stop()

    data = api_get(f"/incidents/{inc_id}")
    if not data:
        st.stop()

    # Header
    col_title, col_badge = st.columns([5, 1])
    with col_title:
        st.markdown(f"# 🔍 {data['id']}")
    with col_badge:
        st.markdown(badge_html(data["label"]), unsafe_allow_html=True)

    with st.expander("🔢 Why this score?"):
        st.markdown(f"**Risk Score: {data['score']}** ({data['label']})")
        for reason in data["reasons"]:
            st.markdown(f"- {reason}")

    st.markdown("---")

    # AI Summary
    st.markdown("## 🤖 AI Summary")
    summary = data.get("summary")
    if not summary or summary.get("status") == "unavailable":
        st.warning("⚠️ AI summary unavailable — see raw alerts below.")
        if summary and summary.get("status") == "unavailable":
            st.caption("Summary unavailable, see raw alerts")
    else:
        title = summary.get("title", "")
        if title:
            st.markdown(f"**{title}**")

        # Display summary with citations highlighted
        summary_text = summary.get("summary", "")
        if summary_text:
            # Build alert lookup for tooltips
            alerts_lookup = {a["id"]: a for a in data.get("alerts", [])}
            import re
            parts = re.split(r"(\[A-\d{3,}\])", summary_text)
            rendered = ""
            for part in parts:
                match = re.fullmatch(r"\[A-(\d{3,})\]", part)
                if match:
                    aid = f"A-{match.group(1)}"
                    alert_info = alerts_lookup.get(aid)
                    tip = alert_info["title"] if alert_info else "Unknown alert"
                    rendered += f'<span title="{tip}" style="background:#2ea04330;color:#56d364;border-radius:3px;padding:1px 5px;font-size:11px;cursor:help;">{part}</span>'
                else:
                    rendered += part.replace("<", "&lt;").replace(">", "&gt;")
            st.markdown(rendered, unsafe_allow_html=True)

        # Validation badge
        validation = data.get("validation")
        if validation:
            st.markdown("#### Citation Verification")
            if validation["passed"]:
                st.markdown('<span class="val-pass">✅ Citations verified</span>', unsafe_allow_html=True)
            else:
                problems = []
                if validation["invalid_citations"]:
                    problems.append(f"Invalid citation IDs: {', '.join(validation['invalid_citations'])}")
                if validation["uncited_sentences"]:
                    problems.append(f"{len(validation['uncited_sentences'])} uncited sentence(s)")
                if validation.get("timeline_invalid_ids"):
                    problems.append(f"Timeline invalid IDs: {', '.join(validation['timeline_invalid_ids'])}")
                problem_str = " | ".join(problems)
                st.markdown(f'<span class="val-fail">⚠️ Verification issues: {problem_str}</span>', unsafe_allow_html=True)

        # Confidence and unknowns
        col_conf, col_unk = st.columns(2)
        with col_conf:
            conf = summary.get("confidence", "unknown")
            st.metric("Confidence", conf.title() if conf else "unknown")
        with col_unk:
            unknowns = summary.get("unknowns", [])
            st.metric("Unknowns", len(unknowns))
            if unknowns:
                for u in unknowns:
                    st.caption(f"• {u}")

    # Generate summary button
    st.markdown("---")
    col_btn1, col_btn2 = st.columns([1, 5])
    with col_btn1:
        if st.button("🔄 Generate/Refresh AI Summary"):
            with st.spinner("Calling LLM API..."):
                resp = api_post(f"/incidents/{inc_id}/summary")
                if resp and resp.status_code == 200:
                    st.success("Summary generated. Refreshing...")
                    time.sleep(0.5)
                    st.rerun()
                elif resp:
                    st.error(f"Failed: {resp.text}")

    # Timeline
    if summary and summary.get("status") != "unavailable":
        timeline = summary.get("timeline", [])
        if timeline:
            st.markdown("## 📅 Attack Timeline")
            tl_data = []
            for entry in timeline:
                tl_data.append({
                    "Time": entry.get("time", ""),
                    "Event": entry.get("event", ""),
                    "Source": entry.get("source_id", ""),
                    "Stage": entry.get("attack_stage", ""),
                })
            st.dataframe(tl_data, use_container_width=True)

    st.markdown("---")

    # Context cards
    st.markdown("## 🔎 Context")
    ctx = data.get("context", {})
    col_user, col_asset, col_intel = st.columns(3)

    with col_user:
        st.markdown("**👤 User Context**")
        user_ctx = ctx.get("user")
        if user_ctx:
            st.markdown(f"""
            <div class="soc-card">
              <b>{user_ctx.get('user', 'unknown')}</b><br>
              Role: {user_ctx.get('role', 'unknown')}<br>
              Dept: {user_ctx.get('dept', 'unknown')}<br>
              Privilege: {user_ctx.get('privilege', 'unknown')}<br>
              Country: {user_ctx.get('usual_country', 'unknown')}
            </div>""", unsafe_allow_html=True)
        else:
            st.markdown('<div class="soc-card">No user context</div>', unsafe_allow_html=True)

    with col_asset:
        st.markdown("**🖥️ Asset Context**")
        asset_ctx = ctx.get("asset")
        if asset_ctx:
            st.markdown(f"""
            <div class="soc-card">
              <b>{asset_ctx.get('host', 'unknown')}</b><br>
              Env: {asset_ctx.get('env', 'unknown')}<br>
              OS: {asset_ctx.get('os', 'unknown')}<br>
              Criticality: {asset_ctx.get('criticality', 'unknown')}<br>
              Owner: {asset_ctx.get('owner', 'unknown')}
            </div>""", unsafe_allow_html=True)
        else:
            st.markdown('<div class="soc-card">No asset context</div>', unsafe_allow_html=True)

    with col_intel:
        st.markdown("**🌐 Threat Intel**")
        intel_ctx = ctx.get("threat_intel")
        if intel_ctx:
            verdict = intel_ctx.get("verdict", "unknown")
            verdict_color = "#ff6b6b" if verdict == "malicious" else "#ffa657" if verdict == "suspicious" else "#56d364"
            tags = ", ".join(intel_ctx.get("tags", [])) or "none"
            st.markdown(f"""
            <div class="soc-card">
              <b>{intel_ctx.get('ip', 'unknown')}</b><br>
              Verdict: <span style="color:{verdict_color};font-weight:600">{verdict}</span><br>
              Confidence: {intel_ctx.get('confidence', 'unknown')}<br>
              Tags: {tags}
            </div>""", unsafe_allow_html=True)
        else:
            st.markdown('<div class="soc-card">No threat intel</div>', unsafe_allow_html=True)

    st.markdown("---")

    # Playbook and actions
    st.markdown("## 🎯 Recommended Playbook")
    playbook_name = data.get("playbook")
    if playbook_name:
        st.markdown(f"**{playbook_name.replace('_', ' ').title()}**")
        llm_reasoning = ""
        if summary and summary.get("status") != "unavailable":
            llm_reasoning = summary.get("playbook_reasoning", "")
        if llm_reasoning:
            st.caption(f"AI reasoning: {llm_reasoning}")
    else:
        st.markdown("No playbook matched.")

    st.markdown("### ⚡ Action Cards")
    st.markdown(
        '<small style="color:#8b949e;">⚠️ Human approval required before execution. '
        'Execution is simulated — no real system will be changed.</small>',
        unsafe_allow_html=True,
    )

    action_cards = data.get("action_cards", [])
    analyst_name = st.text_input("Your analyst name", value="analyst-1", key="analyst_name")

    for card in action_cards:
        action_id = card["action_id"]
        with st.expander(f"🔧 {card['action_id']} — {card['action'].replace('_', ' ').title()}"):
            st.markdown(f"**Target:** `{card['target'] or 'unknown'}`")
            st.markdown(f"**Impact:** {card['impact']}")
            st.markdown(f"**Risk:** {card['risk']}")

            if card.get("warnings"):
                for w in card["warnings"]:
                    st.warning(f"⚠️ {w}")

            # Status from DB
            status = card.get("status", "pending")
            status_color = {"approved": "#56d364", "rejected": "#ff6b6b", "pending": "#8b949e"}
            color = status_color.get(status, "#8b949e")
            st.markdown(
                f"**Status:** <span style='color:{color}'>{status.title()}</span>",
                unsafe_allow_html=True,
            )

            comment = st.text_area("Comment", key=f"comment_{action_id}", placeholder="Optional comment...")

            col_approve, col_reject, col_execute = st.columns(3)

            with col_approve:
                if st.button("✅ Approve", key=f"approve_{action_id}"):
                    resp = api_post(
                        f"/actions/{action_id}/decision",
                        payload={"decision": "approved", "analyst": analyst_name, "comment": comment},
                    )
                    if resp and resp.status_code == 200:
                        st.success("Approved!")
                        time.sleep(0.3)
                        st.rerun()
                    elif resp:
                        st.error(f"Error: {resp.text}")

            with col_reject:
                if st.button("❌ Reject", key=f"reject_{action_id}"):
                    resp = api_post(
                        f"/actions/{action_id}/decision",
                        payload={"decision": "rejected", "analyst": analyst_name, "comment": comment},
                    )
                    if resp and resp.status_code == 200:
                        st.warning("Rejected.")
                        time.sleep(0.3)
                        st.rerun()
                    elif resp:
                        st.error(f"Error: {resp.text}")

            with col_execute:
                # Execute button only shown if DB status is approved
                if status == "approved":
                    if st.button("▶️ Execute (Simulated)", key=f"execute_{action_id}"):
                        resp = api_post(
                            f"/actions/{action_id}/execute",
                            params={"analyst": analyst_name},
                        )
                        if resp:
                            if resp.status_code == 200:
                                result_data = resp.json()
                                st.success(
                                    f"✅ {result_data['status'].title()} — "
                                    f"{result_data.get('label', 'Simulated: no real system changed')}"
                                )
                            elif resp.status_code == 403:
                                st.error("🚫 Blocked by backend: action not approved.")
                            else:
                                st.error(f"Error {resp.status_code}: {resp.text}")
                else:
                    st.markdown(
                        '<small style="color:#8b949e;">🔒 Human approval required</small>',
                        unsafe_allow_html=True,
                    )

    # Raw alerts
    st.markdown("---")
    st.markdown("## 📄 Raw Alerts")
    with st.expander("Show all alerts in this incident"):
        for alert in data.get("alerts", []):
            sev = alert.get("severity", 0)
            st.markdown(
                f"**[{alert['id']}]** {sev_label(sev)} &nbsp; `{alert['source']}` — {alert['title']}",
                unsafe_allow_html=True,
            )
            st.code(alert.get("raw", ""), language="text")


# ============================================================
# VIEW 3: AUDIT LOG
# ============================================================
elif view == "📜 Audit Log":
    st.markdown("# 📜 Audit Log")
    data = api_get("/audit")
    if data:
        rows = data.get("audit_log", [])
        if not rows:
            st.info("No audit log entries yet.")
        else:
            st.caption(f"Showing {len(rows)} entries, newest first.")
            display = []
            for row in rows:
                display.append({
                    "ID": row["id"],
                    "Timestamp": row["timestamp"],
                    "Analyst": row["analyst"],
                    "Event": row["event"],
                    "Action ID": row.get("action_id", ""),
                    "Details": row.get("details", ""),
                })
            st.dataframe(display, use_container_width=True)


# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
st.markdown("""
<div class="footer">
  <b>How it works:</b>
  1️⃣ Alerts loaded &amp; enriched →
  2️⃣ Correlated by shared entities →
  3️⃣ Risk scored →
  4️⃣ AI cited summary generated →
  5️⃣ Analyst approves playbook actions
  <br><br>
  ⚠️ <b>Demo data is synthetic</b> (generated by generate_data.py, seed=42).
  All execution is simulated — no real systems are changed.
</div>
""", unsafe_allow_html=True)
