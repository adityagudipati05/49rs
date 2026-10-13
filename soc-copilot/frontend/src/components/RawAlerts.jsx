import { useRef, useImperativeHandle, forwardRef, useState } from 'react';
import { deleteAlert } from '../api.js';

// Chevron icon
function ChevronIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}

// Trash icon
function TrashIcon() {
  return (
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <polyline points="3 6 5 6 21 6" />
      <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
    </svg>
  );
}

function sevLabel(sev) {
  const map = { 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical' };
  return map[sev] || String(sev);
}

/**
 * RawAlerts — collapsible list of all alerts.
 * Exposes a scrollToAlert(alertId) method via ref.
 * highlighted: set of alertIds that should be visually highlighted.
 */
const RawAlerts = forwardRef(function RawAlerts({ alerts, analyst = 'analyst-1', onAlertRemoved }, ref) {
  const detailsRef = useRef(null);
  const alertRefs = useRef({});
  const [highlighted, setHighlighted] = useState(new Set());
  const [deletingId, setDeletingId] = useState(null);

  useImperativeHandle(ref, () => ({
    scrollToAlert(alertId) {
      // Open the collapsible if closed
      if (detailsRef.current && !detailsRef.current.open) {
        detailsRef.current.open = true;
      }
      const el = alertRefs.current[alertId];
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        setHighlighted(prev => new Set([...prev, alertId]));
        setTimeout(() => {
          setHighlighted(prev => {
            const next = new Set(prev);
            next.delete(alertId);
            return next;
          });
        }, 1500);
      }
    }
  }));

  async function handleDelete(alertId) {
    if (!window.confirm(`Are you sure you want to remove manual alert ${alertId}?`)) {
      return;
    }
    setDeletingId(alertId);
    try {
      const res = await deleteAlert(alertId, analyst || 'analyst-1');
      if (res.status === 200) {
        if (onAlertRemoved) {
          await onAlertRemoved(alertId);
        }
      } else {
        const text = await res.text();
        alert(`Failed to remove alert: ${text}`);
      }
    } catch (err) {
      alert(`Network error: ${err.message}`);
    } finally {
      setDeletingId(null);
    }
  }

  if (!alerts || alerts.length === 0) return null;

  return (
    <details className="collapsible" ref={detailsRef} id="raw-alerts">
      <summary>
        <span>Raw Alerts ({alerts.length})</span>
        <span className="collapsible-chevron"><ChevronIcon /></span>
      </summary>
      <div className="collapsible-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {alerts.map(alert => {
          const sev = alert.severity || 0;
          const sevClass = `sev-${sev}`;
          const isHighlighted = highlighted.has(alert.id);
          const isManual = alert.origin === 'manual';
          return (
            <div
              key={alert.id}
              ref={el => { alertRefs.current[alert.id] = el; }}
              className={`card${isHighlighted ? ' alert-highlighted' : ''}`}
              id={`alert-${alert.id}`}
              style={{ padding: 14 }}
            >
              <div className="alert-row-header" style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
                <span className="alert-row-id">{alert.id}</span>
                <span className={`sev-label ${sevClass}`}>{sevLabel(sev)}</span>
                <span className="alert-row-source">{alert.source}</span>
                <span className={`origin-pill ${isManual ? 'manual' : 'seeded'}`}>
                  {isManual ? 'Manual' : 'Seeded'}
                </span>
                <span className="alert-row-title" style={{ flex: 1 }}>{alert.title}</span>
                {isManual && (
                  <button
                    type="button"
                    className="btn btn-danger btn-xs"
                    id={`delete-raw-${alert.id}`}
                    onClick={() => handleDelete(alert.id)}
                    disabled={deletingId === alert.id}
                    aria-label={`Remove manual alert ${alert.id}`}
                  >
                    <TrashIcon /> Remove
                  </button>
                )}
              </div>
              <pre className="raw-log">{alert.raw || ''}</pre>
            </div>
          );
        })}
      </div>
    </details>
  );
});

export default RawAlerts;
