import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { fetchIncidents, API_BASE } from '../api.js';
import RiskBadge from '../components/RiskBadge.jsx';
import StatBox from '../components/StatBox.jsx';

// Refresh icon
function RefreshIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <polyline points="23 4 23 10 17 10" />
      <polyline points="1 20 1 14 7 14" />
      <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
    </svg>
  );
}

// Skeleton rows for loading state
function SkeletonRow() {
  return (
    <div className="incident-row" style={{ marginBottom: 8 }}>
      <div className="incident-row-bar" style={{ background: 'var(--border-strong)' }} />
      <div className="incident-row-inner" style={{ gap: 12 }}>
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div className="skeleton skeleton-line" style={{ width: '40%' }} />
          <div className="skeleton skeleton-line" style={{ width: '70%' }} />
          <div className="skeleton skeleton-line" style={{ width: '55%' }} />
        </div>
      </div>
    </div>
  );
}

export default function IncidentQueue() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const d = await fetchIncidents();
      setData(d);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  const stats = data?.stats;
  const incidents = data?.incidents || [];

  return (
    <div>
      {/* Page header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Incident Queue</h1>
          <p className="page-header-sub">
            Incidents sorted by risk score — highest first
          </p>
        </div>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={load}
          disabled={loading}
          id="refresh-incidents"
          aria-label="Refresh incident list"
        >
          <RefreshIcon />
          Refresh
        </button>
      </div>

      {/* Error banner */}
      {error && (
        <div className="error-banner" role="alert">
          <span className="error-banner-text">
            Cannot reach API at {API_BASE}. Is <code>uvicorn api:app</code> running?
            <br />
            <span style={{ fontSize: 12, opacity: 0.8 }}>{error}</span>
          </span>
          <button type="button" className="btn btn-secondary" onClick={load} id="retry-queue">
            Retry
          </button>
        </div>
      )}

      {/* Stat boxes */}
      {loading && !data ? (
        <div className="stat-grid">
          {[0,1,2,3].map(i => (
            <div key={i} className="stat-box">
              <div className="skeleton skeleton-line" style={{ width: '60%' }} />
              <div className="skeleton skeleton-line" style={{ width: '40%', height: 28, marginTop: 6 }} />
            </div>
          ))}
        </div>
      ) : stats ? (
        <div className="stat-grid">
          <StatBox label="Total Alerts" value={stats.total_alerts} />
          <StatBox label="Incidents" value={stats.incident_count} />
          <StatBox label="Noise Reduction" value={`${stats.noise_reduction_pct}%`} accent />
          <StatBox label="Unlinked Alerts" value={stats.unlinked_count} />
        </div>
      ) : null}

      <hr className="divider" />

      {/* Incident list */}
      {loading && !data ? (
        <>
          <SkeletonRow />
          <SkeletonRow />
          <SkeletonRow />
        </>
      ) : !error && incidents.length === 0 ? (
        <div className="empty-state">
          <p>No incidents found.</p>
        </div>
      ) : (
        incidents.map(inc => {
          const entities = inc.entities || {};
          const users = (entities.users || []).join(', ') || '—';
          const hosts = (entities.hosts || []).join(', ') || '—';
          const ips = (entities.ips || []).join(', ') || '—';
          const sources = (inc.sources || []).join(', ') || '—';
          const labelCls = (inc.label || 'low').toLowerCase();

          return (
            <div key={inc.id} className="incident-row">
              <div className={`incident-row-bar ${labelCls}`} aria-hidden="true" />
              <div className="incident-row-inner">
                <div className="incident-row-content">
                  <div className="incident-row-header">
                    <span className="incident-row-id">{inc.id}</span>
                    <RiskBadge label={inc.label} />
                    <span className="incident-row-score">Score: {inc.score}</span>
                  </div>
                  <div className="incident-row-meta">
                    Alerts: {inc.alert_count} &nbsp;|&nbsp; Sources: {sources}
                  </div>
                  <div className="incident-row-entities">
                    {users !== '—' && (
                      <span className="entity-chip" title="Users">{users}</span>
                    )}
                    {hosts !== '—' && (
                      <span className="entity-chip" title="Hosts">{hosts}</span>
                    )}
                    {ips !== '—' && (
                      <span className="entity-chip" title="IPs">{ips}</span>
                    )}
                    {users === '—' && hosts === '—' && ips === '—' && (
                      <span className="entity-chip">—</span>
                    )}
                  </div>
                  {inc.top_reason && (
                    <div className="incident-row-reason" title={inc.top_reason}>
                      {inc.top_reason}
                    </div>
                  )}
                </div>
                <div className="incident-row-action">
                  <button
                    type="button"
                    className="btn btn-ghost"
                    onClick={() => navigate(`/incidents/${encodeURIComponent(inc.id)}`)}
                    id={`open-${inc.id}`}
                    aria-label={`Open incident ${inc.id}`}
                  >
                    Open
                  </button>
                </div>
              </div>
            </div>
          );
        })
      )}
    </div>
  );
}
