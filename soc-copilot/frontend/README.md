# SOC Copilot — React Frontend

A clean, modern dark-theme single-page application built with **Vite + React 18 (JSX)** that replaces the legacy Streamlit UI (`app.py`). All data comes from the FastAPI backend — no hardcoded values.

---

## Prerequisites

- **Node.js** v18+ and npm
- **Python 3.10+** with the project dependencies installed

---

## Running the backend

```bash
cd soc-copilot
pip install -r requirements.txt
uvicorn api:app --port 8000
```

The API will be available at `http://localhost:8000`.

---

## Running the frontend

```bash
cd soc-copilot/frontend
npm install
npm run dev
```

Open `http://localhost:5173` in your browser.

---

## Environment variable

The API base URL defaults to `http://localhost:8000`. To override it:

```bash
# Copy the example file
cp .env.example .env

# Then edit .env:
VITE_API_BASE=http://your-backend-host:8000
```

The variable is read at build time by Vite, so you must rebuild after changing it.

---

## Production build

```bash
npm run build
npm run preview  # preview the built output
```

---

## Routes

| Path | Page |
|------|------|
| `/` | Incident Queue |
| `/incidents/:id` | Incident Detail |
| `/audit` | Audit Log |

---

## Design system

All design tokens are CSS variables in `src/styles.css`. No raw hex values exist in JSX — every colour is a token. The accent colour (yellow `#f5c542`) is used only for active nav, primary buttons, citation pills, and the Noise Reduction stat. Risk/status colours use separate semantic tokens.

---

## Files created (none of the Python backend was modified)

```
frontend/
  package.json
  vite.config.js
  index.html
  .env.example
  README.md
  src/
    main.jsx
    App.jsx
    styles.css
    api.js
    components/
      Sidebar.jsx
      Footer.jsx
      RiskBadge.jsx
      StatBox.jsx
      CitedSummary.jsx
      VerificationBadge.jsx
      TimelineTable.jsx
      ContextCards.jsx
      ActionCard.jsx
      RawAlerts.jsx
    pages/
      IncidentQueue.jsx
      IncidentDetail.jsx
      AuditLog.jsx
```
