/**
 * StatusBadge — colored status indicator.
 * Used in Accounts, Alerts, Actors.
 */
const COLORS = {
  active: 'var(--green)',
  monitoring: 'var(--cyan)',
  suspended: 'var(--amber)',
  compromised: 'var(--red)',
  open: 'var(--amber)',
  acknowledged: 'var(--cyan)',
  resolved: 'var(--green)',
  false_positive: 'var(--text-muted)',
  critical: 'var(--red)',
  high: '#ff7c2a',
  medium: 'var(--amber)',
  low: 'var(--cyan)',
}

export default function StatusBadge({ status }) {
  const color = COLORS[status] || 'var(--text-muted)'
  return (
    <span className="status-badge" style={{ color, borderColor: color }}>
      {(status || 'unknown').toUpperCase()}
    </span>
  )
}
