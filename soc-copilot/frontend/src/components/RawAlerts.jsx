import { useRef, useImperativeHandle, forwardRef, useState } from 'react';

// Chevron icon
function ChevronIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <polyline points="6 9 12 15 18 9" />
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
const RawAlerts = forwardRef(function RawAlerts({ alerts }, ref) {
  const detailsRef = useRef(null);
  const alertRefs = useRef({});
  const [highlighted, setHighlighted] = useState(new Set());

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
          return (
            <div
              key={alert.id}
              ref={el => { alertRefs.current[alert.id] = el; }}
              className={`card${isHighlighted ? ' alert-highlighted' : ''}`}
              id={`alert-${alert.id}`}
              style={{ padding: 14 }}
            >
              <div className="alert-row-header">
                <span className="alert-row-id">{alert.id}</span>
                <span className={`sev-label ${sevClass}`}>{sevLabel(sev)}</span>
                <span className="alert-row-source">{alert.source}</span>
                <span className="alert-row-title">{alert.title}</span>
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
