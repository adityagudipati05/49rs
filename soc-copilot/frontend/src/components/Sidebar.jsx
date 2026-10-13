import { NavLink, useParams } from 'react-router-dom';
import { API_BASE } from '../api.js';

// Shield SVG icon (16px, stroke 1.75, currentColor)
function ShieldIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

// Queue icon
function QueueIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="3" y="3" width="7" height="7" />
      <rect x="14" y="3" width="7" height="7" />
      <rect x="14" y="14" width="7" height="7" />
      <rect x="3" y="14" width="7" height="7" />
    </svg>
  );
}

// Bell alert icon
function BellAlertIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
      <path d="M13.73 21a2 2 0 0 1-3.46 0" />
    </svg>
  );
}

// Audit icon
function AuditIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <line x1="16" y1="13" x2="8" y2="13" />
      <line x1="16" y1="17" x2="8" y2="17" />
      <polyline points="10 9 9 9 8 9" />
    </svg>
  );
}

// Incident icon
function IncidentIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="8" x2="12" y2="12" />
      <line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
  );
}

// Chat/Diagnose icon
function ChatIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
    </svg>
  );
}

export default function Sidebar() {
  const params = useParams();
  const currentId = params.id;

  return (
    <nav className="sidebar" aria-label="Main navigation">
      {/* Logo */}
      <div className="sidebar-logo">
        <span style={{ color: 'var(--accent)' }}>
          <ShieldIcon />
        </span>
        <div>
          <div className="sidebar-logo-text">SOC Copilot</div>
          <div className="sidebar-logo-sub">AI-assisted triage</div>
        </div>
      </div>

      {/* Nav links */}
      <div className="sidebar-nav">
        <div className="sidebar-nav-label">Navigation</div>

        <NavLink
          to="/"
          end
          className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
        >
          <QueueIcon />
          Incident Queue
        </NavLink>

        <NavLink
          to="/alerts"
          className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
        >
          <BellAlertIcon />
          Alerts
        </NavLink>

        <NavLink
          to="/diagnose"
          className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
          id="nav-diagnose"
        >
          <ChatIcon />
          Diagnose
        </NavLink>

        <NavLink
          to="/audit"
          className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
        >
          <AuditIcon />
          Audit Log
        </NavLink>

        {/* Show current incident in sidebar when on detail page */}
        {currentId && (
          <div className="sidebar-incident-section">
            <div className="sidebar-nav-label" style={{ paddingTop: 12 }}>Current Incident</div>
            <div className="sidebar-incident-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ color: 'var(--accent)' }}><IncidentIcon /></span>
                <span className="sidebar-incident-id">{currentId}</span>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 4 }}>
                Detail view
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="sidebar-footer">
        <div className="sidebar-footer-note">Demo data is synthetic (seed=42)</div>
        <div className="sidebar-footer-api">API: {API_BASE}</div>
      </div>
    </nav>
  );
}
