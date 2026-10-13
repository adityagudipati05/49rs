import { useState, useEffect, useRef, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { fetchIncident, triggerSummary, fetchCaseNote, API_BASE } from '../api.js';
import RiskBadge from '../components/RiskBadge.jsx';
import CitedSummary from '../components/CitedSummary.jsx';
import VerificationBadge from '../components/VerificationBadge.jsx';
import TimelineTable from '../components/TimelineTable.jsx';
import ContextCards from '../components/ContextCards.jsx';
import ActionCard from '../components/ActionCard.jsx';
import RawAlerts from '../components/RawAlerts.jsx';

// Chevron for collapsible
function ChevronIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}

// Arrow left for back link
function ArrowLeftIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <line x1="19" y1="12" x2="5" y2="12" />
      <polyline points="12 19 5 12 12 5" />
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

// Zap icon for generate
function ZapIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
    </svg>
  );
}

// Warn icon
function WarnIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}

export default function IncidentDetail() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [summaryError, setSummaryError] = useState(null);
  const [caseNoteLoading, setCaseNoteLoading] = useState(false);
  const [copySuccess, setCopySuccess] = useState(false);
  const [analyst, setAnalyst] = useState('analyst-1');
  const rawAlertsRef = useRef(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const d = await fetchIncident(id);
      setData(d);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  async function handleGenerateSummary() {
    setSummaryLoading(true);
    setSummaryError(null);
    try {
      const res = await triggerSummary(id);
      if (res.ok) {
        await load(); // refetch to get the new summary
      } else {
        const text = await res.text();
        setSummaryError(`Failed: ${text}`);
      }
    } catch (err) {
      setSummaryError(`Network error: ${err.message}`);
    } finally {
      setSummaryLoading(false);
    }
  }

  async function handleCopyCaseNote() {
    setCaseNoteLoading(true);
    try {
      const res = await fetchCaseNote(id);
      await navigator.clipboard.writeText(res.markdown);
      setCopySuccess(true);
      setTimeout(() => setCopySuccess(false), 2000);
    } catch (err) {
      alert(`Failed to copy case note: ${err.message}`);
    } finally {
      setCaseNoteLoading(false);
    }
  }

  async function handleDownloadCaseNote() {
    setCaseNoteLoading(true);
    try {
      const res = await fetchCaseNote(id);
      const blob = new Blob([res.markdown], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${id}-case-note.md`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      alert(`Failed to download case note: ${err.message}`);
    } finally {
      setCaseNoteLoading(false);
    }
  }

  function handleCitationClick(alertId) {
    if (rawAlertsRef.current) {
      rawAlertsRef.current.scrollToAlert(alertId);
    }
  }

  // Loading skeleton
  if (loading && !data) {
    return (
      <div>
        <div className="page-header">
          <div style={{ flex: 1 }}>
            <div className="skeleton skeleton-line" style={{ width: '30%', height: 24 }} />
          </div>
        </div>
        <div className="detail-layout">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {[...Array(4)].map((_, i) => (
              <div key={i} className="card" style={{ padding: 20 }}>
                <div className="skeleton skeleton-line" style={{ width: '60%' }} />
                <div className="skeleton skeleton-line" style={{ width: '80%' }} />
                <div className="skeleton skeleton-line" style={{ width: '50%' }} />
              </div>
            ))}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div className="card" style={{ padding: 20 }}>
              <div className="skeleton skeleton-line" style={{ width: '40%', height: 40 }} />
              <div className="skeleton skeleton-line" style={{ width: '60%' }} />
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    const is404 = error.includes('404');
    return (
      <div>
        <div className="card" style={{ padding: 32, textAlign: 'center' }}>
          <div style={{ marginBottom: 12, fontSize: 18, fontWeight: 600, color: 'var(--text)' }}>
            Incident {id} Not Found
          </div>
          <p style={{ color: 'var(--text-muted)', marginBottom: 20, maxWidth: 500, margin: '0 auto 20px' }}>
            {is404
              ? 'This incident no longer exists or was renumbered/merged after alerts were modified.'
              : `Cannot reach API at ${API_BASE}: ${error}`}
          </p>
          <div style={{ display: 'flex', justifyContent: 'center', gap: 10 }}>
            <Link to="/" className="btn btn-primary" id="return-to-queue">
              <ArrowLeftIcon /> Return to Incident Queue
            </Link>
            {!is404 && (
              <button type="button" className="btn btn-secondary" onClick={load} id="retry-detail">
                Retry
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }

  if (!data) return null;

  const summary = data.summary;
  const summaryAvailable = summary && summary.status !== 'unavailable';
  const isSummaryStale = summary && summary.summary_stale === true;
  const alerts = data.alerts || [];
  const alertsLookup = Object.fromEntries(alerts.map(a => [a.id, a]));
  const playbook = data.playbook;
  const playbookDisplay = playbook
    ? playbook.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
    : null;
  const playbookReasoning = summaryAvailable ? summary?.playbook_reasoning : null;
  const actionCards = data.action_cards || [];
  const unknowns = summaryAvailable ? (summary.unknowns || []) : [];
  const confidence = summaryAvailable ? (summary.confidence || 'unknown') : 'unknown';

  return (
    <div>
      {/* Back link + header */}
      <div className="page-header">
        <div>
          <div style={{ marginBottom: 8 }}>
            <Link to="/" className="btn btn-ghost" style={{ height: 'auto', padding: '4px 0', border: 'none' }} id="back-to-queue">
              <ArrowLeftIcon /> Incident Queue
            </Link>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <h1 className="page-title" style={{ fontFamily: 'ui-monospace, "JetBrains Mono", Menlo, monospace' }}>
              {data.id}
            </h1>
            <RiskBadge label={data.label} />
          </div>
          <p className="page-header-sub">
            Score: {data.score} &nbsp;|&nbsp; {(data.sources || []).join(', ')} &nbsp;|&nbsp; {data.alert_ids?.length || 0} alerts
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={handleCopyCaseNote}
            disabled={caseNoteLoading}
            id="copy-case-note"
            aria-label="Copy case note markdown"
          >
            {copySuccess ? 'Copied!' : 'Copy case note'}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={handleDownloadCaseNote}
            disabled={caseNoteLoading}
            id="download-case-note"
            aria-label="Download case note markdown"
          >
            Download .md
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={load}
            disabled={loading}
            id="refresh-detail"
            aria-label="Refresh incident data"
          >
            <RefreshIcon /> Refresh
          </button>
        </div>
      </div>

      {/* Prompt Injection Warning Banner */}
      {data.injection_findings && data.injection_findings.length > 0 && (
        <div
          className="warning-banner"
          role="alert"
          style={{ marginBottom: 16, borderLeft: '4px solid #ef4444' }}
          id="injection-warning-banner"
        >
          <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <WarnIcon />
            <strong>
              Possible prompt injection detected in {Array.from(new Set(data.injection_findings.map(f => f.alert_id))).join(', ')}. Alert text was treated as data, not instructions.
            </strong>
          </span>
        </div>
      )}

      {/* Two-column detail layout */}
      <div className="detail-layout">
        {/* LEFT: AI Summary, Timeline, Raw Alerts */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

          {/* AI Summary card */}
          <div className="card">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12, flexWrap: 'wrap', gap: 8 }}>
              <h2 className="section-heading">AI Summary</h2>
              <button
                type="button"
                className={`btn ${isSummaryStale ? 'btn-primary btn-highlight' : 'btn-primary'}`}
                onClick={handleGenerateSummary}
                disabled={summaryLoading}
                id="generate-summary"
                aria-label="Generate or refresh AI summary"
              >
                {summaryLoading ? <span className="spinner" /> : <ZapIcon />}
                {summaryLoading ? 'Generating...' : 'Generate / Refresh AI Summary'}
              </button>
            </div>

            {/* Stale summary banner */}
            {isSummaryStale && (
              <div
                className="warning-banner"
                role="alert"
                style={{ marginBottom: 12 }}
                id="stale-summary-banner"
              >
                <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <WarnIcon />
                  <strong>Summary is out of date, regenerate</strong>
                </span>
              </div>
            )}

            {summaryError && (
              <div className="result-banner error" role="alert" style={{ marginBottom: 12 }}>
                {summaryError}
              </div>
            )}

            {!summaryAvailable ? (
              <div>
                <div className="info-banner" role="status" aria-label="AI summary unavailable">
                  AI summary unavailable — see raw alerts below.
                </div>
                <p className="caption" style={{ marginTop: 8 }}>
                  Summary unavailable, see raw alerts
                </p>
              </div>
            ) : (
              <div>
                {summary.demo_source && (
                  <div
                    style={{
                      fontSize: 12,
                      color: 'var(--text-muted)',
                      backgroundColor: 'rgba(255, 255, 255, 0.05)',
                      padding: '4px 8px',
                      borderRadius: 4,
                      display: 'inline-block',
                      marginBottom: 10,
                    }}
                    id="demo-source-label"
                  >
                    Pre-generated demo summary (real LLM output)
                  </div>
                )}
                {summary.title && (
                  <div className="card-title" style={{ marginBottom: 10 }}>{summary.title}</div>
                )}

                {/* Verification badge */}
                <VerificationBadge validation={data.validation} />

                {/* Cited summary text */}
                {summary.summary && (
                  <CitedSummary
                    text={summary.summary}
                    alertsLookup={alertsLookup}
                    onCitationClick={handleCitationClick}
                  />
                )}

                {/* Confidence and unknowns */}
                <div className="conf-row">
                  <div className="conf-box">
                    <div className="conf-box-label">Confidence</div>
                    <div className="conf-box-value">
                      {confidence ? String(confidence) : 'unknown'}
                    </div>
                  </div>
                  <div className="conf-box">
                    <div className="conf-box-label">Unknowns ({unknowns.length})</div>
                    {unknowns.length > 0 ? (
                      <ul className="unknowns-list">
                        {unknowns.map((u, i) => (
                          <li key={i}>• {u}</li>
                        ))}
                      </ul>
                    ) : (
                      <div className="conf-box-value">—</div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Timeline */}
          {summaryAvailable && summary.timeline && summary.timeline.length > 0 ? (
            <TimelineTable timeline={summary.timeline} isBasic={false} />
          ) : (data.timeline_basic && data.timeline_basic.length > 0 ? (
            <TimelineTable timeline={data.timeline_basic} isBasic={true} />
          ) : null)}

          {/* Context (mobile — shows below summary, before raw alerts) */}
          <div style={{ display: 'none' }} className="context-mobile">
            <ContextCards context={data.context} />
          </div>

          {/* Raw Alerts */}
          <RawAlerts ref={rawAlertsRef} alerts={alerts} analyst={analyst} onAlertRemoved={load} />
        </div>

        {/* RIGHT: Risk score, Why this score, Context, Playbook, Action cards */}
        <div className="detail-right">

          {/* Risk score card + collapsible reasons */}
          <details className="collapsible risk-score-card" id="why-score">
            <summary style={{ gap: 12 }}>
              <div>
                <div className="risk-score-number">{data.score}</div>
                <RiskBadge label={data.label} />
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, color: 'var(--text-muted)' }}>
                Why this score?
                <span className="collapsible-chevron"><ChevronIcon /></span>
              </div>
            </summary>
            <div className="collapsible-body">
              <ul className="risk-reasons-list">
                {(data.reasons || []).map((reason, i) => (
                  <li key={i}>{reason}</li>
                ))}
              </ul>
            </div>
          </details>

          {/* Context cards */}
          <ContextCards context={data.context} />

          {/* Playbook */}
          {playbookDisplay ? (
            <div className="playbook-card">
              <div className="micro-label" style={{ marginBottom: 6 }}>Recommended Playbook</div>
              <div className="playbook-name">{playbookDisplay}</div>
              {playbookReasoning && (
                <div className="playbook-reasoning">AI reasoning: {playbookReasoning}</div>
              )}
            </div>
          ) : (
            <div className="card">
              <div className="micro-label" style={{ marginBottom: 6 }}>Recommended Playbook</div>
              <p style={{ fontSize: 13, color: 'var(--text-faint)' }}>No playbook matched.</p>
            </div>
          )}

          {/* Action cards */}
          {actionCards.length > 0 && (
            <div>
              <h2 className="section-heading" style={{ marginBottom: 8 }}>Action Cards</h2>
              <p className="caption" style={{ marginBottom: 12, color: 'var(--warning-text)' }}>
                Human approval required before execution. Execution is simulated, no real system will be changed.
              </p>

              {/* Analyst name input */}
              <div className="analyst-section">
                <div className="analyst-label">Analyst Name</div>
                <input
                  type="text"
                  className="input"
                  id="analyst-name"
                  value={analyst}
                  onChange={e => setAnalyst(e.target.value)}
                  placeholder="Your analyst name"
                  aria-label="Analyst name"
                />
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {actionCards.map(card => (
                  <ActionCard
                    key={card.action_id}
                    card={card}
                    analyst={analyst}
                    onRefetch={load}
                  />
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
