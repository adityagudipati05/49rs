/**
 * RiskBadge — pill badge coloured by risk label.
 * label: "Critical" | "High" | "Medium" | "Low" (case-insensitive)
 */
export default function RiskBadge({ label }) {
  if (!label) return null;
  const cls = label.toLowerCase();
  return (
    <span className={`risk-badge ${cls}`} role="img" aria-label={`Risk: ${label}`}>
      {label}
    </span>
  );
}
