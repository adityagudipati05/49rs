/**
 * VerificationBadge — shows validation.passed as success/warning banner.
 * Rules:
 *   - if validation is null/undefined → render nothing
 *   - success ONLY if validation.passed === true
 *   - warning otherwise, listing the actual problems
 * Never defaults to success without explicit validation.passed === true.
 */

function CheckIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function AlertIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}

export default function VerificationBadge({ validation }) {
  if (!validation) return null;

  if (validation.passed === true) {
    return (
      <div className="verification-badge success" role="status" aria-label="Citations verified">
        <span className="verification-badge-icon"><CheckIcon /></span>
        <span>Citations verified — all alert IDs found and sentences cited.</span>
      </div>
    );
  }

  // Build problems list from real data only
  const problems = [];
  if (validation.invalid_citations && validation.invalid_citations.length > 0) {
    problems.push(`Invalid citation IDs: ${validation.invalid_citations.join(', ')}`);
  }
  if (validation.uncited_sentences && validation.uncited_sentences.length > 0) {
    problems.push(`${validation.uncited_sentences.length} uncited sentence(s)`);
  }
  if (validation.timeline_invalid_ids && validation.timeline_invalid_ids.length > 0) {
    problems.push(`Timeline invalid IDs: ${validation.timeline_invalid_ids.join(', ')}`);
  }
  const problemText = problems.length > 0 ? problems.join(' | ') : 'Verification issues detected';

  return (
    <div className="verification-badge warning" role="alert" aria-label="Verification issues">
      <span className="verification-badge-icon"><AlertIcon /></span>
      <span>Verification issues: {problemText}</span>
    </div>
  );
}
