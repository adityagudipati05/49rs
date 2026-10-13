/**
 * api.js — all fetch wrappers for the SOC Copilot FastAPI backend.
 * API base URL from VITE_API_BASE env var, defaulting to localhost:8000.
 */

export const API_BASE =
  typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_BASE
    ? import.meta.env.VITE_API_BASE
    : 'http://localhost:8000';

async function request(method, path, { body, params } = {}) {
  let url = `${API_BASE}${path}`;
  if (params) {
    const qs = new URLSearchParams(params).toString();
    url = `${url}?${qs}`;
  }

  const options = {
    method,
    headers: {},
  };

  if (body !== undefined) {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(body);
  }

  const response = await fetch(url, options);
  return response; // caller handles status checking
}

// GET /incidents
export async function fetchIncidents() {
  const res = await request('GET', '/incidents');
  if (!res.ok) throw new Error(`GET /incidents failed: ${res.status}`);
  return res.json();
}

// GET /incidents/{id}
export async function fetchIncident(id) {
  const res = await request('GET', `/incidents/${encodeURIComponent(id)}`);
  if (!res.ok) throw new Error(`GET /incidents/${id} failed: ${res.status}`);
  return res.json();
}

// POST /incidents/{id}/summary
export async function triggerSummary(id) {
  const res = await request('POST', `/incidents/${encodeURIComponent(id)}/summary`);
  return res; // return raw response so caller can check status
}

// POST /actions/{action_id}/decision
export async function postDecision(actionId, decision, analyst, comment) {
  const res = await request('POST', `/actions/${encodeURIComponent(actionId)}/decision`, {
    body: { decision, analyst, comment: comment || null },
  });
  return res;
}

// POST /actions/{action_id}/execute?analyst=<name>
export async function executeAction(actionId, analyst) {
  const res = await request('POST', `/actions/${encodeURIComponent(actionId)}/execute`, {
    params: { analyst },
  });
  return res;
}

// GET /audit
export async function fetchAuditLog() {
  const res = await request('GET', '/audit');
  if (!res.ok) throw new Error(`GET /audit failed: ${res.status}`);
  return res.json();
}

// GET /alerts?origin=manual|seeded
export async function fetchAlerts(origin) {
  const params = origin ? { origin } : undefined;
  const res = await request('GET', '/alerts', { params });
  if (!res.ok) throw new Error(`GET /alerts failed: ${res.status}`);
  return res.json();
}

// POST /alerts
export async function addAlert(body) {
  const res = await request('POST', '/alerts', { body });
  return res; // caller checks status
}

// DELETE /alerts/{id}?analyst=<name>
export async function deleteAlert(alertId, analyst) {
  const res = await request('DELETE', `/alerts/${encodeURIComponent(alertId)}`, {
    params: { analyst },
  });
  return res;
}

// GET /alerts/ungrouped
export async function fetchUngroupedAlerts() {
  const res = await request('GET', '/alerts/ungrouped');
  if (!res.ok) throw new Error(`GET /alerts/ungrouped failed: ${res.status}`);
  return res.json();
}

// POST /chat
export async function sendChatMessage(message, sessionId, analyst = 'analyst-1') {
  const res = await request('POST', '/chat', {
    body: { message, session_id: sessionId, analyst },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Chat error (${res.status}): ${text}`);
  }
  return res.json();
}

