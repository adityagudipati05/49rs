import { useState, useEffect } from 'react';
import { fetchAuditLog, API_BASE } from '../api.js';

function safeDetails(details) {
  if (!details) return '—';
  if (typeof details === 'string') {
    try {
      const parsed = JSON.parse(details);
      return JSON.stringify(parsed, null, 2);
    } catch {
      return details;
    }
  }
  if (typeof details === 'object') {
    return JSON.stringify(details, null, 2);
  }
  return String(details);
}

export default function AuditLog() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const d = await fetchAuditLog();
      setData(d);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  const rows = data?.audit_log || [];

  return (
    <div>
      {/* Page header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Audit Log</h1>
          <p className="page-header-sub">All analyst actions and system events</p>
        </div>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={load}
          disabled={loading}
          id="refresh-audit"
          aria-label="Refresh audit log"
        >
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
          <button type="button" className="btn btn-secondary" onClick={load} id="retry-audit">
            Retry
          </button>
        </div>
      )}

      {/* Skeleton */}
      {loading && !data && (
        <div className="data-table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                {['ID', 'Timestamp', 'Analyst', 'Event', 'Action ID', 'Details'].map(h => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[...Array(5)].map((_, i) => (
                <tr key={i}>
                  {[...Array(6)].map((__, j) => (
                    <td key={j}>
                      <div className="skeleton skeleton-line" style={{ width: j === 5 ? '80%' : '60%' }} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && rows.length === 0 && (
        <div className="empty-state">
          <p>No audit log entries yet.</p>
        </div>
      )}

      {/* Table */}
      {rows.length > 0 && (
        <div>
          <p className="table-caption">
            Showing {rows.length} {rows.length === 1 ? 'entry' : 'entries'}, newest first.
          </p>
          <div className="data-table-wrap">
            <table className="data-table" aria-label="Audit log">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Timestamp</th>
                  <th>Analyst</th>
                  <th>Event</th>
                  <th>Action ID</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(row => (
                  <tr key={row.id}>
                    <td className="mono-cell" style={{ whiteSpace: 'nowrap' }}>{row.id}</td>
                    <td className="mono-cell" style={{ whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>
                      {row.timestamp}
                    </td>
                    <td>{row.analyst || '—'}</td>
                    <td>
                      <span style={{
                        fontWeight: 600,
                        fontSize: 12,
                        color: row.event?.includes('BLOCK') || row.event?.includes('REJECT')
                          ? 'var(--danger-text)'
                          : row.event?.includes('EXEC')
                          ? 'var(--low-text)'
                          : 'var(--text-muted)'
                      }}>
                        {row.event || '—'}
                      </span>
                    </td>
                    <td className="mono-cell">{row.action_id || '—'}</td>
                    <td>
                      {row.details ? (
                        <pre style={{
                          margin: 0,
                          fontFamily: 'ui-monospace, "JetBrains Mono", Menlo, monospace',
                          fontSize: 11.5,
                          color: 'var(--text-muted)',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-word',
                          maxWidth: 280,
                        }}>
                          {safeDetails(row.details)}
                        </pre>
                      ) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
