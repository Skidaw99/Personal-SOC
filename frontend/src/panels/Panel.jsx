/**
 * Panel — base floating panel component.
 *
 * Renders a glassmorphism card with header.
 * Positioning is 100% CSS-driven — the panelId maps to
 * .panel-{id} which is positioned per threat state in index.css.
 */
import { useThreatState } from '../engine/threatState'

export default function Panel({
  panelId,
  title,
  icon,
  children,
  scanline = false,
  status,
  className = '',
}) {
  const { isCritical } = useThreatState()

  const dotColor = isCritical ? 'var(--red)' : 'var(--cyan)'
  const dotShadow = isCritical ? '0 0 8px var(--red-glow)' : '0 0 8px var(--cyan-glow)'

  return (
    <div className={`panel panel-${panelId} ${scanline ? 'panel-scanline' : ''} ${className}`}>
      <div className="panel-header">
        <span className="panel-dot" style={{ background: dotColor, boxShadow: dotShadow }} />
        {icon && <span className="panel-icon">{icon}</span>}
        <span className="panel-title">{title}</span>
        {status && <span className="panel-status">{status}</span>}
      </div>
      <div className="panel-body">
        {children}
      </div>
    </div>
  )
}
