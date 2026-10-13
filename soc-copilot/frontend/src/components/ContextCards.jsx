/**
 * ContextCards — three cards: User, Asset, Threat Intel.
 * Shows "No user context" / "No asset context" / "No threat intel" when null.
 * Missing fields show "unknown". Verdict color: malicious=danger, suspicious=warning, else success.
 * No dangerouslySetInnerHTML. All values are plain React text nodes.
 */

function UserIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </svg>
  );
}

function ServerIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
      <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
      <line x1="6" y1="6" x2="6.01" y2="6" />
      <line x1="6" y1="18" x2="6.01" y2="18" />
    </svg>
  );
}

function GlobeIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="10" />
      <line x1="2" y1="12" x2="22" y2="12" />
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </svg>
  );
}

function ContextRow({ label, value }) {
  return (
    <div className="context-row">
      <span className="context-row-key">{label}</span>
      <span className="context-row-val">{value || 'unknown'}</span>
    </div>
  );
}

function verdictClass(verdict) {
  if (!verdict) return '';
  if (verdict === 'malicious') return 'verdict-malicious';
  if (verdict === 'suspicious') return 'verdict-suspicious';
  return 'verdict-clean';
}

export default function ContextCards({ context }) {
  const userCtx = context?.user;
  const assetCtx = context?.asset;
  const intelCtx = context?.threat_intel;

  return (
    <div>
      <h2 className="section-heading" style={{ marginBottom: 12 }}>Context</h2>
      <div className="context-grid">
        {/* User */}
        <div className="context-card">
          <div className="context-card-title">
            <UserIcon /> User Context
          </div>
          {userCtx ? (
            <>
              <div className="context-card-name">{userCtx.user || 'unknown'}</div>
              <ContextRow label="Role" value={userCtx.role} />
              <ContextRow label="Dept" value={userCtx.dept} />
              <ContextRow label="Privilege" value={userCtx.privilege} />
              <ContextRow label="Country" value={userCtx.usual_country} />
            </>
          ) : (
            <p style={{ fontSize: 13, color: 'var(--text-faint)' }}>No user context</p>
          )}
        </div>

        {/* Asset */}
        <div className="context-card">
          <div className="context-card-title">
            <ServerIcon /> Asset Context
          </div>
          {assetCtx ? (
            <>
              <div className="context-card-name">{assetCtx.host || 'unknown'}</div>
              <ContextRow label="Env" value={assetCtx.env} />
              <ContextRow label="OS" value={assetCtx.os} />
              <ContextRow label="Criticality" value={assetCtx.criticality} />
              <ContextRow label="Owner" value={assetCtx.owner} />
            </>
          ) : (
            <p style={{ fontSize: 13, color: 'var(--text-faint)' }}>No asset context</p>
          )}
        </div>

        {/* Threat Intel */}
        <div className="context-card">
          <div className="context-card-title">
            <GlobeIcon /> Threat Intel
          </div>
          {intelCtx ? (
            <>
              <div className="context-card-name">{intelCtx.ip || 'unknown'}</div>
              <div className="context-row">
                <span className="context-row-key">Verdict</span>
                <span className={`context-row-val ${verdictClass(intelCtx.verdict)}`}>
                  {intelCtx.verdict || 'unknown'}
                </span>
              </div>
              <ContextRow label="Confidence" value={intelCtx.confidence} />
              <div className="context-row">
                <span className="context-row-key">Tags</span>
                <span className="context-row-val">
                  {intelCtx.tags && intelCtx.tags.length > 0 ? intelCtx.tags.join(', ') : 'none'}
                </span>
              </div>
            </>
          ) : (
            <p style={{ fontSize: 13, color: 'var(--text-faint)' }}>No threat intel</p>
          )}
        </div>
      </div>
    </div>
  );
}
