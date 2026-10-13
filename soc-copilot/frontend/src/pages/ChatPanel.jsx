import { useState, useEffect, useRef } from 'react';
import { sendChatMessage, fetchUngroupedAlerts, API_BASE } from '../api.js';

function BotIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 8V4H8" />
      <rect x="4" y="8" width="16" height="12" rx="2" />
      <path d="M2 14h2" />
      <path d="M20 14h2" />
      <path d="M15 13v2" />
      <path d="M9 13v2" />
    </svg>
  );
}

function SendIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <line x1="22" y1="2" x2="11" y2="13" />
      <polygon points="22 2 15 22 11 13 2 9 22 2" />
    </svg>
  );
}

function ShieldAlertIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <line x1="12" y1="8" x2="12" y2="12" />
      <line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
  );
}

export default function ChatPanel() {
  const [messages, setMessages] = useState([
    {
      id: 'welcome',
      sender: 'assistant',
      text: 'Hello Analyst. I am the Alert Diagnosis Copilot. Enter any alert number (e.g. A-007, 007, alert 13, #13) to diagnose whether it should be promoted to a new incident, merged with an existing one, or dismissed as noise.',
      diagnosis: null,
      citationsValid: true,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [ungroupedCount, setUngroupedCount] = useState(null);
  const [sessionId] = useState(() => `sess-${Date.now().toString(36)}`);
  const [promotedAlerts, setPromotedAlerts] = useState(new Set());
  const messagesEndRef = useRef(null);

  useEffect(() => {
    fetchUngroupedAlerts()
      .then(d => setUngroupedCount(d.count))
      .catch(() => {});
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  async function handleSend(textToSend) {
    const msg = (textToSend || input).trim();
    if (!msg || loading) return;

    setError(null);
    setInput('');

    const userMsg = {
      id: `u-${Date.now()}`,
      sender: 'user',
      text: msg,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages(prev => [...prev, userMsg]);
    setLoading(true);

    try {
      const res = await sendChatMessage(msg, sessionId, 'analyst-1');
      const botMsg = {
        id: `b-${Date.now()}`,
        sender: 'assistant',
        text: res.reply,
        diagnosis: res.diagnosis,
        citationsValid: res.citations_valid,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages(prev => [...prev, botMsg]);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function handlePromote(alertId) {
    setPromotedAlerts(prev => new Set([...prev, alertId]));
    handleSend(`Promote ${alertId} to incident review`);
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Alert Diagnosis Chatbot</h1>
          <p className="page-header-sub">
            Investigate ungrouped alerts, evaluate near-miss correlations, and receive AI-backed triage recommendations
          </p>
        </div>
        {ungroupedCount !== null && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className="entity-chip" style={{ fontSize: 12 }}>
              {ungroupedCount} Ungrouped Alerts
            </span>
          </div>
        )}
      </div>

      {error && (
        <div className="error-banner" role="alert" style={{ marginBottom: 16 }}>
          <span className="error-banner-text">
            Chatbot Error: {error}
          </span>
          <button type="button" className="btn btn-secondary btn-xs" onClick={() => setError(null)}>
            Dismiss
          </button>
        </div>
      )}

      <div className="chat-container">
        {/* Chat header */}
        <div className="chat-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ color: 'var(--accent)' }}><BotIcon /></span>
            <span style={{ fontWeight: 600, fontSize: 13.5 }}>Copilot Triage Engine</span>
            <span style={{ fontSize: 11, color: 'var(--text-faint)' }}>Session: {sessionId}</span>
          </div>
          <span style={{ fontSize: 11, color: 'var(--low-text)' }}>● Online (Groq / Deterministic)</span>
        </div>

        {/* Messages */}
        <div className="chat-messages" id="chat-messages">
          {messages.map(m => {
            const isUser = m.sender === 'user';
            const diag = m.diagnosis;

            return (
              <div key={m.id} className={`chat-bubble-row ${m.sender}`}>
                <div className={`chat-avatar ${m.sender}`}>
                  {isUser ? 'AN' : <BotIcon />}
                </div>

                <div className={`chat-bubble ${m.sender}`}>
                  {/* Text Reply */}
                  <div style={{ whiteSpace: 'pre-wrap', lineHeight: 1.55 }}>
                    {m.text}
                  </div>

                  {/* Diagnosis Card if available */}
                  {diag && (
                    <div className="diagnosis-card" id={`diagnosis-${diag.alert_id}`}>
                      {/* Card Header */}
                      <div className="diagnosis-header">
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{ fontWeight: 700, fontSize: 15, color: 'var(--text)' }}>
                            {diag.alert_id}
                          </span>
                          <span className={`origin-pill ${diag.grouping_status === 'ungrouped' ? 'seeded' : 'manual'}`}>
                            {diag.grouping_status === 'ungrouped' ? 'Ungrouped' : `In ${diag.grouping_status}`}
                          </span>
                        </div>

                        {/* Recommendation badge */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span
                            className="sev-label"
                            style={{
                              background: diag.incident_recommendation.includes('promote')
                                ? 'var(--critical-bg)'
                                : diag.incident_recommendation.includes('merge')
                                ? 'var(--medium-bg)'
                                : 'var(--neutral-bg)',
                              color: diag.incident_recommendation.includes('promote')
                                ? 'var(--critical-text)'
                                : diag.incident_recommendation.includes('merge')
                                ? 'var(--medium-text)'
                                : 'var(--neutral-text)',
                              border: '1px solid var(--border)',
                              fontSize: 11.5,
                              fontWeight: 600,
                            }}
                          >
                            Recommendation: {diag.incident_recommendation.toUpperCase()} ({diag.recommendation_confidence} conf)
                          </span>
                        </div>
                      </div>

                      {/* Prompt injection banner if detected */}
                      {diag.prompt_injection_findings && diag.prompt_injection_findings.length > 0 && (
                        <div
                          style={{
                            padding: '8px 12px',
                            background: 'var(--critical-bg)',
                            border: '1px solid var(--critical-border)',
                            borderRadius: 'var(--radius-sm)',
                            color: 'var(--critical-text)',
                            fontSize: 12,
                            display: 'flex',
                            gap: 8,
                            alignItems: 'center',
                          }}
                        >
                          <ShieldAlertIcon />
                          <span>
                            <strong>Security Alert:</strong> Prompt injection attempt detected in payload.
                            Untrusted instructions were filtered from LLM reasoning.
                          </span>
                        </div>
                      )}

                      {/* Metric Grid */}
                      <div className="diagnosis-metric-grid">
                        <div className="diagnosis-metric-box">
                          <div className="diagnosis-metric-label">Risk Score Estimate</div>
                          <div className="diagnosis-metric-value" style={{ color: 'var(--accent)' }}>
                            {diag.risk_score_estimate} pts
                          </div>
                        </div>

                        <div className="diagnosis-metric-box">
                          <div className="diagnosis-metric-label">Asset Criticality</div>
                          <div className="diagnosis-metric-value">
                            {diag.enrichment.asset_criticality !== null ? `Level ${diag.enrichment.asset_criticality}` : 'None'}
                          </div>
                        </div>

                        <div className="diagnosis-metric-box">
                          <div className="diagnosis-metric-label">User Privilege</div>
                          <div className="diagnosis-metric-value">
                            {diag.enrichment.user_privilege !== null ? `Level ${diag.enrichment.user_privilege}` : 'None'}
                          </div>
                        </div>

                        <div className="diagnosis-metric-box">
                          <div className="diagnosis-metric-label">Threat Intel</div>
                          <div className="diagnosis-metric-value" style={{
                            color: diag.enrichment.threat_intel_verdict === 'malicious' ? 'var(--critical-text)' :
                                   diag.enrichment.threat_intel_verdict === 'suspicious' ? 'var(--warning-text)' : 'var(--text)'
                          }}>
                            {diag.enrichment.threat_intel_verdict || 'Benign / None'}
                          </div>
                        </div>
                      </div>

                      {/* Near-miss correlations */}
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 6 }}>
                          Near-miss Correlations ({diag.near_miss_correlations?.length || 0}):
                        </div>
                        {diag.near_miss_correlations && diag.near_miss_correlations.length > 0 ? (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                            {diag.near_miss_correlations.map(nm => (
                              <button
                                key={nm.alert_id}
                                type="button"
                                className="quick-chip"
                                onClick={() => handleSend(nm.alert_id)}
                                title={`Lookup ${nm.alert_id}: ${nm.reason}`}
                                style={{ textAlign: 'left' }}
                              >
                                <strong>{nm.alert_id}</strong> &bull; {nm.reason}
                              </button>
                            ))}
                          </div>
                        ) : (
                          <div style={{ fontSize: 11.5, color: 'var(--text-faint)' }}>
                            No near-miss correlations found.
                          </div>
                        )}
                      </div>

                      {/* Next Steps */}
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 6 }}>
                          Recommended Playbook Next Steps:
                        </div>
                        <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12.5, color: 'var(--text)' }}>
                          {diag.next_steps?.map(s => (
                            <li key={s.step} style={{ marginBottom: 4 }}>
                              {s.description}
                            </li>
                          ))}
                        </ul>
                      </div>

                      {/* Promote action button */}
                      {diag.grouping_status === 'ungrouped' && (
                        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 4 }}>
                          <button
                            type="button"
                            className="btn btn-primary btn-xs"
                            disabled={promotedAlerts.has(diag.alert_id)}
                            onClick={() => handlePromote(diag.alert_id)}
                          >
                            {promotedAlerts.has(diag.alert_id) ? '✓ Promoted for Review' : 'Promote to Incident Review (Simulated)'}
                          </button>
                        </div>
                      )}
                    </div>
                  )}

                  <div style={{ fontSize: 10, color: 'var(--text-faint)', marginTop: 6, textAlign: isUser ? 'right' : 'left' }}>
                    {m.timestamp}
                  </div>
                </div>
              </div>
            );
          })}

          {loading && (
            <div className="chat-bubble-row assistant">
              <div className="chat-avatar assistant"><BotIcon /></div>
              <div className="chat-bubble assistant" style={{ fontStyle: 'italic', color: 'var(--text-muted)' }}>
                Analyzing alert entities, correlations, and threat intel...
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Quick action chips */}
        <div className="quick-chips">
          <span style={{ fontSize: 11.5, color: 'var(--text-faint)', alignSelf: 'center', marginRight: 4 }}>Quick:</span>
          <button type="button" className="quick-chip" onClick={() => handleSend('list ungrouped')} id="chip-list">
            list ungrouped
          </button>
          <button type="button" className="quick-chip" onClick={() => handleSend('group')} id="chip-group">
            group
          </button>
          <button type="button" className="quick-chip" onClick={() => handleSend('help')} id="chip-help">
            help
          </button>
          <button type="button" className="quick-chip" onClick={() => handleSend('A-013')} id="chip-a013">
            A-013 (Ungrouped)
          </button>
          <button type="button" className="quick-chip" onClick={() => handleSend('A-007')} id="chip-a007">
            A-007 (Injection check)
          </button>
          <button type="button" className="quick-chip" onClick={() => handleSend('why?')} id="chip-why">
            why?
          </button>
        </div>

        {/* Input Bar */}
        <form
          className="chat-input-bar"
          onSubmit={e => {
            e.preventDefault();
            handleSend();
          }}
        >
          <input
            type="text"
            className="chat-input"
            id="chat-input"
            placeholder="Type alert ID (e.g. A-007, 007, alert 13, #13) or command..."
            value={input}
            onChange={e => setInput(e.target.value)}
            disabled={loading}
          />
          <button
            type="submit"
            className="btn btn-primary"
            id="chat-send"
            disabled={loading || !input.trim()}
          >
            <SendIcon /> Send
          </button>
        </form>
      </div>
    </div>
  );
}
