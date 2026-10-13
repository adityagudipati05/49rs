/**
 * StatBox — one of four stat boxes in the queue header.
 * Props: label (string), value (string|number), accent (bool)
 */
export default function StatBox({ label, value, accent }) {
  return (
    <div className="stat-box">
      <div className="micro-label">{label}</div>
      <div className={`stat-number${accent ? ' accent' : ''}`}>{value ?? '—'}</div>
    </div>
  );
}
