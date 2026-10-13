import { useState } from 'react';
import { postDecision, executeAction } from '../api.js';

// Warning triangle icon
function WarnIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}

// Lock icon
function LockIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  );
}

// Status pill
function StatusPill({ status }) {
  const s = (status || 'pending').toLowerCase();
  return <span className={`status-pill ${s}`}>{s}</span>;
}

/**
 * ActionCard — one action from action_cards[].
 * Props: card (API object), analyst (string), onRefetch (fn)
 * Execute button only when card.status === "approved" (server value).
 * No optimistic state — always refetch after any action.
 */
export default function ActionCard({ card, analyst, onRefetch }) {
  const [comment, setComment] = useState('');
  const [loading, setLoading] = useState(null); // 'approve' | 'reject' | 'execute' | null
  const [result, setResult] = useState(null);   // { type: 'success'|'error', text: string }

  const status = card.status || 'pending';
  const isApproved = status === 'approved';

  async function handleDecision(decision) {
    if (!analyst.trim()) {
      setResult({ type: 'error', text: 'Analyst name is required.' });
      return;
    }
    setLoading(decision === 'approved' ? 'approve' : 'reject');
    setResult(null);
    try {
      const res = await postDecision(card.action_id, decision, analyst, comment);
      if (res.ok) {
        setResult({ type: 'success', text: `Decision recorded: ${decision}` });
        setComment('');
        await onRefetch();
      } else {
        const text = await res.text();
        setResult({ type: 'error', text: `Error: ${text}` });
      }
    } catch (err) {
      setResult({ type: 'error', text: `Network error: ${err.message}` });
    } finally {
      setLoading(null);
    }
  }

  async function handleExecute() {
    setLoading('execute');
    setResult(null);
    try {
      const res = await executeAction(card.action_id, analyst);
      if (res.status === 200) {
        const data = await res.json();
        setResult({ type: 'success', text: `${data.status} — ${data.label || ''}` });
        await onRefetch();
      } else if (res.status === 403) {
        setResult({ type: 'error', text: 'Blocked by backend: action not approved.' });
      } else {
        const text = await res.text();
        setResult({ type: 'error', text: `Error ${res.status}: ${text}` });
      }
    } catch (err) {
      setResult({ type: 'error', text: `Network error: ${err.message}` });
    } finally {
      setLoading(null);
    }
  }

  const actionLabel = card.action
    ? card.action.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
    : card.action_id;

  return (
    <div className="action-card" id={`action-${card.action_id}`}>
      {/* Header */}
      <div className="action-card-header">
        <div className="action-card-title">{actionLabel}</div>
        <StatusPill status={status} />
      </div>

      {/* Meta */}
      <div className="action-card-meta">
        <span className="action-meta-key">ID</span>
        <span className="action-meta-val mono-cell">{card.action_id}</span>

        <span className="action-meta-key">Target</span>
        <span className="action-meta-val mono-cell">{card.target || 'unknown'}</span>

        <span className="action-meta-key">Impact</span>
        <span className="action-meta-val">{card.impact || 'unknown'}</span>

        <span className="action-meta-key">Risk</span>
        <span className="action-meta-val">{card.risk || 'unknown'}</span>
      </div>

      {/* Warnings */}
      {card.warnings && card.warnings.length > 0 && (
        <div>
          {card.warnings.map((w, i) => (
            <div key={i} className="warning-callout">
              <span className="warning-callout-icon"><WarnIcon /></span>
              <span>{w}</span>
            </div>
          ))}
        </div>
      )}

      {/* Comment */}
      <div className="field">
        <label className="field-label" htmlFor={`comment-${card.action_id}`}>
          Comment (optional)
        </label>
        <textarea
          id={`comment-${card.action_id}`}
          className="textarea"
          value={comment}
          onChange={e => setComment(e.target.value)}
          placeholder="Add a comment before approving or rejecting..."
          rows={2}
        />
      </div>

      {/* Result banner */}
      {result && (
        <div className={`result-banner ${result.type}`} role={result.type === 'error' ? 'alert' : 'status'}>
          {result.text}
        </div>
      )}

      {/* Approval label + buttons */}
      <div className="action-approval-label">
        <LockIcon />
        {isApproved
          ? 'Approved — execution available.'
          : 'Human approval required before execution. Execution is simulated, no real system will be changed.'}
      </div>

      <div className="action-button-row">
        <button
          type="button"
          className="btn btn-approve"
          onClick={() => handleDecision('approved')}
          disabled={loading !== null}
          id={`approve-${card.action_id}`}
          aria-label={`Approve action ${card.action_id}`}
        >
          {loading === 'approve' ? <span className="spinner" /> : null}
          Approve
        </button>

        <button
          type="button"
          className="btn btn-reject"
          onClick={() => handleDecision('rejected')}
          disabled={loading !== null}
          id={`reject-${card.action_id}`}
          aria-label={`Reject action ${card.action_id}`}
        >
          {loading === 'reject' ? <span className="spinner" /> : null}
          Reject
        </button>

        {isApproved && (
          <button
            type="button"
            className="btn btn-execute"
            onClick={handleExecute}
            disabled={loading !== null}
            id={`execute-${card.action_id}`}
            aria-label={`Execute action ${card.action_id} (simulated)`}
          >
            {loading === 'execute' ? <span className="spinner" /> : null}
            Execute
            <span className="simulated-tag">Simulated</span>
          </button>
        )}
      </div>
    </div>
  );
}
