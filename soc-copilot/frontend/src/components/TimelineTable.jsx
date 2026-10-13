/**
 * TimelineTable — renders the attack timeline from summary.timeline.
 * Columns: Time, Event, Source, Stage.
 * Only rendered when summary is available and timeline is non-empty.
 */
export default function TimelineTable({ timeline, isBasic = false }) {
  if (!timeline || timeline.length === 0) return null;

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12, flexWrap: 'wrap', gap: 8 }}>
        <h2 className="section-heading" style={{ marginBottom: 0 }}>Attack Timeline</h2>
        {isBasic && (
          <span style={{ fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic' }} id="timeline-basic-label">
            Built from alert timestamps (not AI)
          </span>
        )}
      </div>
      <div className="data-table-wrap">
        <table className="data-table" aria-label="Attack timeline">
          <thead>
            <tr>
              <th>Time</th>
              <th>Event</th>
              <th>Source</th>
              <th>Stage</th>
            </tr>
          </thead>
          <tbody>
            {timeline.map((entry, i) => (
              <tr key={i}>
                <td className="mono-cell" style={{ whiteSpace: 'nowrap' }}>
                  {entry.time || '—'}
                </td>
                <td>{entry.event || '—'}</td>
                <td className="mono-cell">{entry.source_id || '—'}</td>
                <td style={{ color: 'var(--text-muted)' }}>{entry.attack_stage || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
