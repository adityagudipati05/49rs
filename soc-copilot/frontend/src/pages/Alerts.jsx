import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { fetchAlerts, fetchIncidents, addAlert, deleteAlert, API_BASE } from '../api.js';

function sevLabel(sev) {
  const map = { 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical' };
  return map[sev] || String(sev);
}

// Plus icon
function PlusIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <line x1="12" y1="5" x2="12" y2="19" />
      <line x1="5" y1="12" x2="19" y2="12" />
    </svg>
  );
}

// Refresh icon
function RefreshIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <polyline points="23 4 23 10 17 10" />
      <polyline points="1 20 1 14 7 14" />
      <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
    </svg>
  );
}

// Trash icon
function TrashIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <polyline points="3 6 5 6 21 6" />
      <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
    </svg>
  );
}

// Close icon
function CloseIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  );
}

const INITIAL_FORM = {
  source: 'identity',
  severity: 2,
  title: '',
  description: '',
  user: '',
  host: '',
  ip: '',
  resource: '',
  timestamp: '',
  raw: '',
  analyst: 'analyst-1',
};

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [triageFilter, setTriageFilter] = useState('all');
  const [originFilter, setOriginFilter] = useState('all');
  const [showModal, setShowModal] = useState(false);
  const [formData, setFormData] = useState(INITIAL_FORM);
  const [submitting, setSubmitting] = useState(false);
  const [fieldErrors, setFieldErrors] = useState({});
  const [banner, setBanner] = useState(null); // { type: 'success' | 'error', text: string }

  async function loadData() {
    setLoading(true);
    setError(null);
    try {
      const [alertsRes, incsRes] = await Promise.all([
        fetchAlerts(),
        fetchIncidents(),
      ]);
      setAlerts(alertsRes.alerts || []);
      setIncidents(incsRes.incidents || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  function handleOpenModal() {
    setFormData(INITIAL_FORM);
    setFieldErrors({});
    setShowModal(true);
  }

  function handleCloseModal() {
    setShowModal(false);
    setFieldErrors({});
  }

  function handleFormChange(e) {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: name === 'severity' ? Number(value) : value,
    }));
    if (fieldErrors[name]) {
      setFieldErrors(prev => {
        const next = { ...prev };
        delete next[name];
        return next;
      });
    }
  }

  async function handleSubmitAlert(e) {
    e.preventDefault();
    setFieldErrors({});

    // Client-side pre-validation
    const clientErrs = {};
    if (!formData.title.trim()) {
      clientErrs.title = 'Title is required';
    }
    if (!formData.analyst.trim()) {
      clientErrs.analyst = 'Analyst name is required';
    }
    const hasEntity = Boolean(
      formData.user.trim() ||
      formData.host.trim() ||
      formData.ip.trim() ||
      formData.resource.trim()
    );
    if (!hasEntity) {
      clientErrs._general = 'At least one entity (user, host, IP, or resource) must be provided.';
    }

    if (Object.keys(clientErrs).length > 0) {
      setFieldErrors(clientErrs);
      return;
    }

    setSubmitting(true);
    try {
      // Build payload, converting empty strings to null or omitting empty
      const payload = {
        source: formData.source,
        severity: Number(formData.severity),
        title: formData.title.trim(),
        analyst: formData.analyst.trim(),
        description: formData.description.trim() || null,
        user: formData.user.trim() || null,
        host: formData.host.trim() || null,
        ip: formData.ip.trim() || null,
        resource: formData.resource.trim() || null,
        timestamp: formData.timestamp.trim() || null,
        raw: formData.raw.trim() || null,
      };

      const res = await addAlert(payload);
      if (res.status === 200) {
        const data = await res.json();
        const addedAlert = data.alert;
        const newIncidents = data.incidents || [];

        // Determine banner message from real before/after response
        const joinedInc = newIncidents.find(inc =>
          inc.alert_ids && inc.alert_ids.includes(addedAlert.id)
        );

        let bannerText = '';
        if (joinedInc) {
          const prevInc = incidents.find(i =>
            i.id === joinedInc.id ||
            (i.alert_ids && i.alert_ids.some(aid => joinedInc.alert_ids.includes(aid)))
          );
          const oldCount = prevInc ? prevInc.alert_count : (joinedInc.alert_count - 1);
          bannerText = `Added ${addedAlert.id}. It joined ${joinedInc.id} (alert count ${oldCount} to ${joinedInc.alert_count})`;
        } else {
          bannerText = `Added ${addedAlert.id}. It is unlinked (no matching alerts in the window)`;
        }

        setBanner({ type: 'success', text: bannerText });
        setShowModal(false);
        // Refresh with latest data
        await loadData();
      } else if (res.status === 422) {
        const errData = await res.json().catch(() => ({}));
        const errors = {};
        if (Array.isArray(errData.detail)) {
          errData.detail.forEach(err => {
            const locKey = err.loc && err.loc.length > 1 ? err.loc[1] : '_general';
            const cleanMsg = err.msg ? err.msg.replace(/^Value error,\s*/i, '') : 'Invalid value';
            errors[locKey] = cleanMsg;
          });
        } else if (typeof errData.detail === 'string') {
          errors._general = errData.detail;
        } else {
          errors._general = 'Validation failed (422)';
        }
        setFieldErrors(errors);
      } else {
        const errText = await res.text();
        setFieldErrors({ _general: `Error (${res.status}): ${errText}` });
      }
    } catch (err) {
      setFieldErrors({ _general: `Network error: ${err.message}` });
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDeleteAlert(alertId) {
    const analyst = formData.analyst || 'analyst-1';
    if (!window.confirm(`Are you sure you want to remove manual alert ${alertId}?`)) {
      return;
    }

    try {
      const res = await deleteAlert(alertId, analyst);
      if (res.status === 200) {
        setBanner({ type: 'success', text: `Removed manual alert ${alertId}. Pipeline re-run.` });
        await loadData();
      } else {
        const errText = await res.text();
        setBanner({ type: 'error', text: `Failed to remove alert: ${errText}` });
      }
    } catch (err) {
      setBanner({ type: 'error', text: `Network error: ${err.message}` });
    }
  }

  const filteredAlerts = alerts.filter(a => {
    if (triageFilter !== 'all' && a.triage !== triageFilter) return false;
    if (originFilter === 'manual' && a.origin !== 'manual') return false;
    if (originFilter === 'seeded' && a.origin === 'manual') return false;
    return true;
  });

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Alerts</h1>
          <p className="page-header-sub">
            All ingested security alerts (seeded synthetic + live analyst-entered)
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={loadData}
            disabled={loading}
            id="refresh-alerts"
            aria-label="Refresh alerts table"
          >
            <RefreshIcon /> Refresh
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={handleOpenModal}
            id="open-add-alert-modal"
          >
            <PlusIcon /> Add Alert
          </button>
        </div>
      </div>

      {/* Result banner */}
      {banner && (
        <div
          className={`result-banner ${banner.type}`}
          role="status"
          style={{ marginBottom: 16 }}
          id="alert-result-banner"
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>{banner.text}</span>
            <button
              type="button"
              className="btn btn-ghost btn-xs"
              onClick={() => setBanner(null)}
              style={{ padding: '0 4px', border: 'none' }}
              aria-label="Dismiss banner"
            >
              <CloseIcon />
            </button>
          </div>
        </div>
      )}

      {/* Error banner */}
      {error && (
        <div className="error-banner" role="alert">
          <span className="error-banner-text">
            Cannot reach API at {API_BASE}.<br />
            <span style={{ fontSize: 12, opacity: 0.8 }}>{error}</span>
          </span>
          <button type="button" className="btn btn-secondary" onClick={loadData} id="retry-alerts">
            Retry
          </button>
        </div>
      )}

      {/* Filter tabs: Triage tabs + Origin toggle */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 12 }}>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button
            type="button"
            className={`btn ${triageFilter === 'all' ? 'btn-secondary' : 'btn-ghost'}`}
            onClick={() => setTriageFilter('all')}
            style={{
              borderColor: triageFilter === 'all' ? 'var(--accent)' : 'var(--border)',
              color: triageFilter === 'all' ? 'var(--accent)' : 'var(--text-muted)',
            }}
            id="filter-all"
          >
            All ({alerts.length})
          </button>
          <button
            type="button"
            className={`btn ${triageFilter === 'in_incident' ? 'btn-secondary' : 'btn-ghost'}`}
            onClick={() => setTriageFilter('in_incident')}
            style={{
              borderColor: triageFilter === 'in_incident' ? 'var(--accent)' : 'var(--border)',
              color: triageFilter === 'in_incident' ? 'var(--accent)' : 'var(--text-muted)',
            }}
            id="filter-in-incident"
          >
            In incident ({alerts.filter(a => a.triage === 'in_incident').length})
          </button>
          <button
            type="button"
            className={`btn ${triageFilter === 'needs_review' ? 'btn-secondary' : 'btn-ghost'}`}
            onClick={() => setTriageFilter('needs_review')}
            style={{
              borderColor: triageFilter === 'needs_review' ? 'var(--accent)' : 'var(--border)',
              color: triageFilter === 'needs_review' ? 'var(--accent)' : 'var(--text-muted)',
            }}
            id="filter-needs-review"
          >
            Needs review ({alerts.filter(a => a.triage === 'needs_review').length})
          </button>
          <button
            type="button"
            className={`btn ${triageFilter === 'low_priority' ? 'btn-secondary' : 'btn-ghost'}`}
            onClick={() => setTriageFilter('low_priority')}
            style={{
              borderColor: triageFilter === 'low_priority' ? 'var(--accent)' : 'var(--border)',
              color: triageFilter === 'low_priority' ? 'var(--accent)' : 'var(--text-muted)',
            }}
            id="filter-low-priority"
          >
            Low priority ({alerts.filter(a => a.triage === 'low_priority').length})
          </button>
        </div>

        {/* Origin filter buttons */}
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 12, color: 'var(--text-muted)' }}>
          <span>Origin:</span>
          <button
            type="button"
            className={`btn btn-xs ${originFilter === 'all' ? 'btn-secondary' : 'btn-ghost'}`}
            onClick={() => setOriginFilter('all')}
            id="filter-origin-all"
          >
            All
          </button>
          <button
            type="button"
            className={`btn btn-xs ${originFilter === 'manual' ? 'btn-secondary' : 'btn-ghost'}`}
            onClick={() => setOriginFilter('manual')}
            id="filter-manual"
          >
            Manual
          </button>
          <button
            type="button"
            className={`btn btn-xs ${originFilter === 'seeded' ? 'btn-secondary' : 'btn-ghost'}`}
            onClick={() => setOriginFilter('seeded')}
            id="filter-seeded"
          >
            Seeded
          </button>
        </div>
      </div>

      {/* Alerts Table */}
      {loading && alerts.length === 0 ? (
        <div className="data-table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                {['ID', 'Time', 'Source', 'Severity', 'Entities', 'Title', 'Triage', 'Origin', 'Actions'].map(h => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[...Array(6)].map((_, i) => (
                <tr key={i}>
                  {[...Array(9)].map((__, j) => (
                    <td key={j}>
                      <div className="skeleton skeleton-line" style={{ width: '70%' }} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : filteredAlerts.length === 0 ? (
        <div className="empty-state">
          <p>No alerts found matching filter.</p>
        </div>
      ) : (
        <div className="data-table-wrap">
          <table className="data-table" id="alerts-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Time (UTC)</th>
                <th>Source</th>
                <th>Severity</th>
                <th>Entities</th>
                <th>Title</th>
                <th>Triage</th>
                <th>Origin</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.map(alert => {
                const isManual = alert.origin === 'manual';
                const entitiesList = [];
                if (alert.user) entitiesList.push(`user: ${alert.user}`);
                if (alert.host) entitiesList.push(`host: ${alert.host}`);
                if (alert.ip) entitiesList.push(`ip: ${alert.ip}`);
                if (alert.resource) entitiesList.push(`resource: ${alert.resource}`);

                return (
                  <tr key={alert.id} id={`row-${alert.id}`}>
                    <td className="mono-cell" style={{ fontWeight: 600 }}>
                      {alert.id}
                    </td>
                    <td className="mono-cell" style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                      {alert.timestamp || 'unknown'}
                    </td>
                    <td>
                      <span className="entity-chip">{alert.source || 'unknown'}</span>
                    </td>
                    <td>
                      <span className={`sev-label sev-${alert.severity || 1}`}>
                        {sevLabel(alert.severity)} ({alert.severity})
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                        {entitiesList.length > 0 ? (
                          entitiesList.map((ent, idx) => (
                            <span key={idx} className="entity-chip" style={{ fontSize: 11 }}>
                              {ent}
                            </span>
                          ))
                        ) : (
                          <span style={{ color: 'var(--text-faint)', fontSize: 12 }}>unknown</span>
                        )}
                      </div>
                    </td>
                    <td style={{ maxWidth: 280 }}>
                      <div style={{ fontWeight: 500 }}>{alert.title}</div>
                      {alert.description && (
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                          {alert.description}
                        </div>
                      )}
                    </td>
                    <td>
                      {alert.triage === 'in_incident' ? (
                        alert.incident_id ? (
                          <Link
                            to={`/incidents/${encodeURIComponent(alert.incident_id)}`}
                            className="triage-pill in-incident"
                            id={`triage-${alert.id}`}
                            title={`View incident ${alert.incident_id}`}
                          >
                            {alert.incident_id}
                          </Link>
                        ) : (
                          <span className="triage-pill in-incident" id={`triage-${alert.id}`}>
                            In incident
                          </span>
                        )
                      ) : alert.triage === 'needs_review' ? (
                        <span className="triage-pill needs-review" id={`triage-${alert.id}`}>
                          Needs review
                        </span>
                      ) : (
                        <span className="triage-pill low-priority" id={`triage-${alert.id}`}>
                          Low priority
                        </span>
                      )}
                    </td>
                    <td>
                      <span className={`origin-pill ${isManual ? 'manual' : 'seeded'}`}>
                        {isManual ? 'Manual' : 'Seeded'}
                      </span>
                    </td>
                    <td>
                      {isManual ? (
                        <button
                          type="button"
                          className="btn btn-danger btn-xs"
                          id={`delete-alert-${alert.id}`}
                          onClick={() => handleDeleteAlert(alert.id)}
                          aria-label={`Remove manual alert ${alert.id}`}
                        >
                          <TrashIcon /> Remove
                        </button>
                      ) : (
                        <span style={{ fontSize: 11, color: 'var(--text-faint)' }}>—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Add Alert Modal */}
      {showModal && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="modal-title">
          <div className="modal-dialog">
            <div className="modal-header">
              <h2 id="modal-title" className="section-heading" style={{ margin: 0 }}>
                Add New Security Alert
              </h2>
              <button
                type="button"
                className="btn btn-ghost btn-xs"
                onClick={handleCloseModal}
                aria-label="Close dialog"
                style={{ border: 'none', padding: '4px' }}
              >
                <CloseIcon />
              </button>
            </div>

            <form onSubmit={handleSubmitAlert}>
              <div className="modal-body">
                {fieldErrors._general && (
                  <div className="result-banner error" role="alert">
                    {fieldErrors._general}
                  </div>
                )}

                {/* Source & Severity Row */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  <div className="field">
                    <label className="field-label" htmlFor="alert-source">
                      Source *
                    </label>
                    <select
                      id="alert-source"
                      name="source"
                      className="select"
                      value={formData.source}
                      onChange={handleFormChange}
                      required
                    >
                      <option value="identity">identity</option>
                      <option value="edr">edr</option>
                      <option value="siem">siem</option>
                      <option value="cloud">cloud</option>
                    </select>
                    {fieldErrors.source && <span className="field-error">{fieldErrors.source}</span>}
                  </div>

                  <div className="field">
                    <label className="field-label" htmlFor="alert-severity">
                      Severity *
                    </label>
                    <select
                      id="alert-severity"
                      name="severity"
                      className="select"
                      value={formData.severity}
                      onChange={handleFormChange}
                      required
                    >
                      <option value={1}>1 - Low</option>
                      <option value={2}>2 - Medium</option>
                      <option value={3}>3 - High</option>
                      <option value={4}>4 - Critical</option>
                    </select>
                    {fieldErrors.severity && <span className="field-error">{fieldErrors.severity}</span>}
                  </div>
                </div>

                {/* Title */}
                <div className="field">
                  <label className="field-label" htmlFor="alert-title">
                    Title * (max 200 chars)
                  </label>
                  <input
                    id="alert-title"
                    name="title"
                    type="text"
                    className="input"
                    maxLength={200}
                    value={formData.title}
                    onChange={handleFormChange}
                    placeholder="e.g. Unusual login from external IP"
                    required
                  />
                  {fieldErrors.title && <span className="field-error">{fieldErrors.title}</span>}
                </div>

                {/* Description */}
                <div className="field">
                  <label className="field-label" htmlFor="alert-description">
                    Description (optional, max 2000 chars)
                  </label>
                  <textarea
                    id="alert-description"
                    name="description"
                    className="textarea"
                    rows={2}
                    maxLength={2000}
                    value={formData.description}
                    onChange={handleFormChange}
                    placeholder="Details about what occurred..."
                  />
                  {fieldErrors.description && <span className="field-error">{fieldErrors.description}</span>}
                </div>

                {/* Entities (at least one required) */}
                <div style={{ borderTop: '1px solid var(--border)', paddingTop: 12 }}>
                  <div className="micro-label" style={{ marginBottom: 8, color: 'var(--text-muted)' }}>
                    Correlatable Entities (provide at least one)
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                    <div className="field">
                      <label className="field-label" htmlFor="alert-user">User</label>
                      <input
                        id="alert-user"
                        name="user"
                        type="text"
                        className="input"
                        maxLength={200}
                        value={formData.user}
                        onChange={handleFormChange}
                        placeholder="e.g. priya.sharma"
                      />
                      {fieldErrors.user && <span className="field-error">{fieldErrors.user}</span>}
                    </div>

                    <div className="field">
                      <label className="field-label" htmlFor="alert-host">Host</label>
                      <input
                        id="alert-host"
                        name="host"
                        type="text"
                        className="input"
                        maxLength={200}
                        value={formData.host}
                        onChange={handleFormChange}
                        placeholder="e.g. prod-db-01"
                      />
                      {fieldErrors.host && <span className="field-error">{fieldErrors.host}</span>}
                    </div>

                    <div className="field">
                      <label className="field-label" htmlFor="alert-ip">IP Address</label>
                      <input
                        id="alert-ip"
                        name="ip"
                        type="text"
                        className="input"
                        maxLength={200}
                        value={formData.ip}
                        onChange={handleFormChange}
                        placeholder="e.g. 198.51.100.24"
                      />
                      {fieldErrors.ip && <span className="field-error">{fieldErrors.ip}</span>}
                    </div>

                    <div className="field">
                      <label className="field-label" htmlFor="alert-resource">Resource (optional)</label>
                      <input
                        id="alert-resource"
                        name="resource"
                        type="text"
                        className="input"
                        maxLength={200}
                        value={formData.resource}
                        onChange={handleFormChange}
                        placeholder="e.g. s3://customer-data"
                      />
                      {fieldErrors.resource && <span className="field-error">{fieldErrors.resource}</span>}
                    </div>
                  </div>
                </div>

                {/* Timestamp & Analyst */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  <div className="field">
                    <label className="field-label" htmlFor="alert-timestamp">
                      Timestamp (optional ISO 8601)
                    </label>
                    <input
                      id="alert-timestamp"
                      name="timestamp"
                      type="text"
                      className="input"
                      value={formData.timestamp}
                      onChange={handleFormChange}
                      placeholder="e.g. 2024-10-10T08:30:00Z"
                    />
                    <span className="field-hint">Defaults to current UTC time if omitted</span>
                    {fieldErrors.timestamp && <span className="field-error">{fieldErrors.timestamp}</span>}
                  </div>

                  <div className="field">
                    <label className="field-label" htmlFor="alert-analyst">
                      Analyst Name *
                    </label>
                    <input
                      id="alert-analyst"
                      name="analyst"
                      type="text"
                      className="input"
                      value={formData.analyst}
                      onChange={handleFormChange}
                      placeholder="Your name"
                      required
                    />
                    {fieldErrors.analyst && <span className="field-error">{fieldErrors.analyst}</span>}
                  </div>
                </div>

                {/* Raw log */}
                <div className="field">
                  <label className="field-label" htmlFor="alert-raw">
                    Raw Log (optional, max 4000 chars)
                  </label>
                  <textarea
                    id="alert-raw"
                    name="raw"
                    className="textarea"
                    rows={2}
                    maxLength={4000}
                    value={formData.raw}
                    onChange={handleFormChange}
                    placeholder="Raw syslog / JSON payload..."
                  />
                  {fieldErrors.raw && <span className="field-error">{fieldErrors.raw}</span>}
                </div>
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={handleCloseModal}
                  disabled={submitting}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={submitting}
                  id="submit-alert"
                >
                  {submitting ? 'Submitting...' : 'Ingest Alert'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
