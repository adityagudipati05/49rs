/**
 * CitedSummary — renders an LLM summary text as plain React nodes,
 * turning [A-NNN] citation references into interactive pills.
 *
 * Security: no dangerouslySetInnerHTML. All text rendered as plain nodes.
 * LLM text and alert titles are untrusted.
 */
export default function CitedSummary({ text, alertsLookup, onCitationClick }) {
  if (!text) return null;

  // Split on [A-NNN] references (3+ digits). Regex must match the API output.
  const parts = text.split(/(\[A-\d{3,}\])/);

  return (
    <p style={{ fontSize: 13.5, lineHeight: 1.65, color: 'var(--text)', margin: 0 }}>
      {parts.map((part, i) => {
        const match = part.match(/^\[A-(\d{3,})\]$/);
        if (match) {
          const alertId = `A-${match[1]}`;
          const alertInfo = alertsLookup ? alertsLookup[alertId] : null;
          // Alert title is untrusted; render as plain text, never as HTML.
          const tipText = alertInfo ? alertInfo.title : 'Unknown alert';
          return (
            <span key={i} className="citation-tooltip">
              <button
                type="button"
                className="citation-pill"
                onClick={() => onCitationClick && onCitationClick(alertId)}
                aria-label={`Citation ${part}: ${tipText}`}
                tabIndex={0}
              >
                {part}
              </button>
              {/* Accessible tooltip — not title-only so screen readers get it */}
              <span className="tooltip-text" role="tooltip">
                {tipText}
              </span>
            </span>
          );
        }
        // Plain text — render as-is, no HTML parsing.
        return <span key={i}>{part}</span>;
      })}
    </p>
  );
}
