/**
 * RiskScore — large colored risk score display.
 * Used in Alerts, Intel, Actors, Dashboard.
 */
function riskColor(s) {
  if (s >= 90) return 'var(--red)'
  if (s >= 70) return '#ff7c2a'
  if (s >= 50) return 'var(--amber)'
  return 'var(--cyan)'
}

export default function RiskScore({ score, size = 28 }) {
  const s = score ?? 0
  const color = riskColor(s)
  return (
    <span className="risk-badge" style={{
      color,
      borderColor: color,
      fontSize: size,
      fontFamily: 'var(--font-display)',
      fontWeight: 700,
    }}>
      {s.toFixed(0)}
    </span>
  )
}
