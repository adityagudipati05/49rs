# SOC AI Copilot

> **AI-powered Security Operations Center alert triage prototype — hackathon project**

---

## What it does

End-to-end flow:

```
alerts.json → enrich → correlate → risk score → LLM cited summary → citation validator
           → playbook action cards → analyst approval (backend-enforced) → audit log
```

### Key features
- **Real correlation**: union-find groups alerts sharing user/host/IP within a 2-hour window
- **Risk scoring**: severity × 2 + asset criticality + user privilege + malicious intel + source diversity
- **LLM summaries**: Groq (primary) or Anthropic generates cited summaries; every sentence ends with `[A-xxx]` references
- **Citation validator**: confirms all citations are real alert IDs from the incident (handles post-period citations cleanly)
- **Deterministic timeline fallback**: alert-timestamp timeline available instantly when offline/without API key
- **Deterministic prompt injection detection**: regex-based detection scans alert fields, warning analysts without changing scores
- **Case note export**: one-click markdown case note generation with standardized heading hierarchy
- **Approval enforcement**: backend (not just UI) enforces that execution requires approval
- **Audit log**: append-only, written only by real events
- **Demo cache**: pre-generated real LLM summaries shipped for zero-config offline demonstrations

---

## Quick start

### 1. Backend setup & dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate synthetic data

```bash
python generate_data.py
```

### 3. Set your API key (optional — Groq primary, Anthropic optional)

Configure via environment variable or in a `.env` file in `soc-copilot/`:

```bash
# In .env:
GROQ_API_KEY=gsk_...

# Or Windows PowerShell
$env:GROQ_API_KEY = "gsk_..."

# Or Linux/macOS
export GROQ_API_KEY="gsk_..."
```

*(Note: ANTHROPIC_API_KEY is also supported as an optional alternative. If no key is set, the system degrades gracefully with deterministic fallback timelines and demo cache).*

### 4. Start the backend

```bash
uvicorn api:app --reload --port 8000
```

### 5. Start the React Frontend (Main UI)

The React single-page application located in `frontend/` is the primary modern UI (Streamlit `app.py` is legacy):

```bash
cd frontend
npm install
npm run dev
```

Open your browser at **http://localhost:5173/**.

*(Legacy Streamlit UI can optionally be run via: `streamlit run app.py` on port 8501).*

### 6. Run tests

```bash
pytest tests/ -v
# or
python -m pytest tests/ -q
```

---

## Project structure

```
soc-copilot/
├── data/
│   ├── alerts.json          # ~40 synthetic alerts (3 attack stories + noise)
│   ├── assets.json          # Asset inventory (host → criticality, env, etc.)
│   ├── users.json           # User registry (privilege, dept, country)
│   ├── threat_intel.json    # IP threat intel (verdict, confidence, tags)
│   ├── playbooks.json       # 3 playbooks with steps
│   └── demo_cache/          # Pre-generated real LLM output for offline demos
├── frontend/                # Modern React (Vite) UI (Primary)
│   ├── src/
│   │   ├── pages/           # IncidentQueue, IncidentDetail, AuditLog, etc.
│   │   ├── components/      # CitedSummary, TimelineTable, ActionCard, etc.
│   │   └── api.js           # API client
│   └── package.json
├── generate_data.py         # Seeded synthetic data generator (seed=42)
├── chatbot.py               # Alert diagnosis chatbot, near-miss correlation, session context
├── injection.py             # Prompt injection detection and alert sanitization
├── pipeline.py              # Enrich → correlate → score
├── llm.py                   # Groq & Anthropic client, caching, validation
├── validator.py             # Citation validator
├── injection.py             # Deterministic prompt injection detector
├── actions.py               # Rule-based playbook selection, action cards
├── db.py                    # SQLite: approvals + audit_log
├── api.py                   # FastAPI backend
├── app.py                   # Streamlit UI (Legacy)
├── scripts/
│   └── export_demo_cache.py # Exports real LLM cache to data/demo_cache/
├── tests/                   # pytest test suite
├── cache/                   # LLM response cache (gitignored)
├── requirements.txt
└── README.md
```

---

## Attack stories (planted in synthetic data)

| Story | Alerts | Entities | Expected Incident |
|---|---|---|---|
| Account Takeover | A-001..A-005 | user=priya.sharma, ip=185.220.101.7 | INC-1 (Critical) |
| Malware on Host | A-006..A-009 | host=FIN-WS-22, ip=45.9.148.12 | INC-2 (Critical) |
| Cloud Exposure | A-010..A-012 | host=s3://finance-reports, ip=103.77.42.19 | INC-3 (High) |

A-007 contains a prompt injection attempt in its description — detected deterministically via `injection.py` and displayed as a security warning in the UI without affecting risk scoring or LLM prompts.

---

## Global rules (no hardcoded values)

1. **All stats computed** — noise_reduction_pct, incident count, scores derive from real data
2. **No fake LLM output** — if API unavailable, shows "Summary unavailable" with no invented text
3. **Cache metadata** — model, timestamp, SHA-256 hash of input; invalidated if input changes
4. **Synthetic data labeled** — `_meta` field in every JSON file; UI footer confirms
5. **Simulated execution** — labeled "Simulated: no real system changed" everywhere
6. **Missing → null** — no invented defaults like `criticality=0`
7. **Audit log is real** — only real events write to it; no seeded rows

---

## API endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/incidents` | Ranked incident list + summary stats |
| GET | `/incidents/{id}` | Full incident detail, injection findings, timeline_basic |
| GET | `/incidents/{id}/case-note` | Standardized markdown case note export |
| POST | `/incidents/{id}/summary` | Trigger LLM summary generation |
| GET | `/alerts` | All alerts with triage status and linked incidents |
| GET | `/alerts/ungrouped` | Uncorrelated alerts (id, severity, short message) |
| POST | `/chat` | Alert diagnosis chatbot (`{message, session_id}`) |
| POST | `/actions/{id}/decision` | Approve or reject an action |
| POST | `/actions/{id}/execute` | Execute (simulated); 403 if not approved |
| GET | `/alerts` | List all alerts (seeded + manual) |
| POST | `/alerts` | Ingest manual alert and recompute pipeline |
| DELETE | `/alerts/{id}` | Delete manual alert |
| GET | `/audit` | Audit log, newest first |

---

## Alert Diagnosis Chatbot

The chatbot allows security analysts to inspect singleton or ungrouped alerts that were not automatically grouped into correlated incidents. Analysts can type alert references in various formats (e.g., `A-007`, `007`, `alert 7`, `#7`), inspect near-miss correlations, ask follow-up questions, and explore clustering opportunities.

### Capabilities
- **Flexible ID Parsing**: Accepts `A-007`, `007`, `alert 7`, `#7`, `alert #13`. Unknown IDs return a helpful message with the valid ID range (`A-001` - `A-040`).
- **Deterministic Diagnosis**:
  - **Summary**: Plain-English description with source, severity, timestamp, user, host, IP.
  - **Enrichment**: Asset criticality, user privilege, threat-intel verdict (null if missing, never invented).
  - **Grouping Status**: Identifies whether the alert is `"ungrouped"` or already bound to an incident (`INC-x`).
  - **Near-Miss Correlations**: Alerts that almost matched (shared user/host/IP outside the 2-hour window, or same source / similar message) along with reasons.
  - **Incident Recommendation**: `"promote to new incident"`, `"merge into INC-x"`, or `"likely noise / dismiss"`, with confidence level and reasoning.
  - **Risk Score Estimate**: Formula matching pipeline scoring (`severity * 2 + criticality + privilege + intel + source_diversity`).
  - **Prompt Injection Defense**: Evaluated via `injection.py`. If detected, raw instructions are sanitized/redacted and the user is warned.
  - **Playbook Next Steps**: 3-5 recommended actions selected via `playbooks.json` and `actions.py`.
- **Conversational Explanation & Citations**:
  - Uses primary LLM (Groq / Anthropic) with SHA-256 input hashing and cache.
  - Every sentence strictly ends with `[A-xxx]` citations and is validated via `validator.py`.
  - Fallback deterministic explanation if no LLM API key is configured.
- **Session Context**: Follow-up questions like `"why?"` or `"what else is related?"` automatically reference the last discussed alert in that session.
- **Audit Logging**: Chatbot lookups are recorded as real events in `audit_log` via `db.py`.

### Example Conversations

#### 1. Diagnosing an Ungrouped Alert
```
User: 013
Bot:  [Card: Diagnosis for A-013]
      Status: Ungrouped | Risk Score: 6/15 | Recommendation: likely noise / dismiss (Low confidence)
      Enrichment: Asset: null, User privilege: standard, Threat intel: null
      Near-misses: A-014 (Same source okta within 2h)
      Next steps:
      - Search Okta system logs for other actions by user Priyasharma
      - Review conditional access policies for unusual login attributes
      - If user confirms legitimate activity, dismiss as benign
      
      Explanation:
      Alert A-013 is an ungrouped medium severity event from Okta [A-013]. Threat intelligence for IP 203.0.113.50 is unavailable [A-013]. Correlation identified 1 near-miss alert [A-013]. Recommendation is likely noise / dismiss [A-013].
```

#### 2. Follow-Up Questions (Context Retained)
```
User: why?
Bot:  Alert A-013 was recommended as likely noise / dismiss because the threat intelligence verdict is clean or absent and severity is low to medium with standard user privileges [A-013].
```
```
User: what else is related?
Bot:  Near-misses for alert A-013: A-014: Same source okta within 2h [A-013].
```

#### 3. Grouping Suggestions Command
```
User: group
Bot:  Found 3 potential correlation groups among ungrouped alerts:
      • Group (source: okta): A-013, A-014 (2 alerts)
      • Group (source: crowdstrike): A-018, A-019 (2 alerts)
      • Group (source: aws_cloudtrail): A-024, A-025 (2 alerts)
```

#### 4. Prompt Injection Defense (Alert A-007)
```
User: A-007
Bot:  [Card: Diagnosis for A-007]
      Status: In Incident INC-2 | Risk Score: 13/15 | Recommendation: merge into INC-2 (High confidence)
      Prompt Injection Warning: Potential prompt injection attempt detected: instruction_override.
      
      Explanation:
      Alert A-007 is already correlated into INC-2 [A-007]. Threat intelligence for IP 45.9.148.12 reports malicious [A-007]. Prompt injection attempt was detected in alert payload and sanitized [A-007].
```

---

## Demo data note

> ⚠️ All data is synthetic, generated by `generate_data.py` with `random.seed(42)`.
> No real security events are represented.
