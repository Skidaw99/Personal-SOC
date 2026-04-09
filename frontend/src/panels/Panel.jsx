/**
 * Panel — base floating panel component.
 *
 * Receives layout from the layout engine and renders as a
 * glass-morphism card at the computed position.
 * All panels extend this base.
 */
import { usePanelLayout } from '../engine/layoutEngine'
import { useThreatState } from '../engine/threatState'

export default function Panel({
  panelId,
  title,
  icon,
  children,
  scanline = false,
  className = '',
}) {
  const layout = usePanelLayout(panelId)
  const { isCritical } = useThreatState()

  if (!layout) return null

  const dotColor = isCritical ? 'var(--red)' : 'var(--cyan)'
  const dotShadow = isCritical
    ? '0 0 8px var(--red-glow)'
    : '0 0 8px var(--cyan-glow)'

  return (
    <div
      className={`panel ${scanline ? 'panel-scanline' : ''} ${className}`}
      style={layout.style}
    >
      <div className="panel-header">
        <span className="dot" style={{ background: dotColor, boxShadow: dotShadow }} />
        {icon && <span style={{ fontSize: '0.85rem' }}>{icon}</span>}
        <span>{title}</span>
      </div>
      <div className="panel-body">
        {children}
      </div>
    </div>
  )
}
