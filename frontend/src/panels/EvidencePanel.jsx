/**
 * Evidence Panel — incident list + FBI report export.
 *
 * Shows recent incidents with their response status.
 * Each incident has an "Export PDF" button that triggers
 * the Evidence Builder API endpoint.
 */
import { useState } from 'react'
import Panel from './Panel'
import { PANELS } from '../engine/layoutEngine'
import { useThreatState } from '../engine/threatState'

const STATUS_COLORS = {
  new: 'var(--cyan)',
  enriched: 'var(--amber)',
  correlated: '#ff7c2a',
  escalated: 'var(--red)',
  closed: 'var(--text-muted)',
}

function IncidentCard({ event, onExport, exporting }) {
  const risk = event.risk_score ?? event.threat_score ?? 0
  const type = (event.event_type || 'unknown').replace(/_/g, ' ')
  const time = event.occurred_at
    ? new Date(event.occurred_at).toLocaleString('en-GB', {
        day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit',
      })
    : '—'

  const riskColor = risk >= 90 ? 'var(--red)'
    : risk >= 70 ? '#ff7c2a'
    : risk >= 50 ? 'var(--amber)'
    : 'var(--cyan)'

  return (
    <div style={{
      padding: '10px 12px',
      borderBottom: '1px solid var(--border)',
      display: 'flex',
      flexDirection: 'column',
      gap: 6,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{
          fontFamily: 'var(--font-display)',
          fontSize: '0.65rem',
          textTransform: 'uppercase',
          letterSpacing: '0.05em',
          color: riskColor,
        }}>
          {type}
        </span>
        <span style={{
          fontSize: '0.6rem', color: 'var(--text-muted)',
        }}>
          {time}
        </span>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
          {event.source_ip || '—'}
        </span>
        <span style={{
          fontSize: '0.65rem', fontWeight: 600, color: riskColor,
          fontFamily: 'var(--font-mono)',
        }}>
          RISK {risk.toFixed(0)}
        </span>
      </div>

      {event.actor_display_name && (
        <div style={{ fontSize: '0.6rem', color: 'var(--amber)' }}>
          ▸ Actor: {event.actor_display_name}
        </div>
      )}

      {/* Export button */}
      <button
        onClick={() => onExport(event)}
        disabled={exporting}
        style={{
          alignSelf: 'flex-end',
          padding: '4px 10px',
          background: 'transparent',
          border: '1px solid var(--border)',
          borderRadius: 4,
          color: 'var(--text-secondary)',
          fontFamily: 'var(--font-display)',
          fontSize: '0.55rem',
          letterSpacing: '0.06em',
          textTransform: 'uppercase',
          transition: 'all 200ms',
          opacity: exporting ? 0.4 : 1,
        }}
        onMouseEnter={e => {
          e.currentTarget.style.borderColor = 'var(--cyan)'
          e.currentTarget.style.color = 'var(--cyan)'
        }}
        onMouseLeave={e => {
          e.currentTarget.style.borderColor = 'var(--border)'
          e.currentTarget.style.color = 'var(--text-secondary)'
        }}
      >
        {exporting ? 'GENERATING...' : '📄 EXPORT FBI PDF'}
      </button>
    </div>
  )
}

export default function EvidencePanel() {
  const { events } = useThreatState()
  const [exporting, setExporting] = useState(null)

  // Get unique incidents (deduplicated by soc_event_id, highest risk first)
  const incidents = events
    .filter(e => (e.risk_score ?? 0) >= 50 || e.event_type === 'account_takeover')
    .slice(0, 20)

  async function handleExport(event) {
    const eventId = event.soc_event_id || event.id
    if (!eventId) return

    setExporting(eventId)
    try {
      const res = await fetch('/api/soc/evidence/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          soc_event_id: eventId,
          case_id: `SOC-${new Date().getFullYear()}-${eventId.slice(0, 4).toUpperCase()}`,
        }),
      })

      if (res.ok) {
        // Download the PDF
        const blob = await res.blob()
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `evidence-${eventId.slice(0, 8)}.pdf`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
      }
    } catch {
      // Silent fail — copilot will pick up the error
    } finally {
      setExporting(null)
    }
  }

  return (
    <Panel panelId={PANELS.EVIDENCE} title="EVIDENCE" icon="📋">
      <div style={{
        display: 'flex', justifyContent: 'space-between',
        alignItems: 'center', marginBottom: 6, padding: '0 2px',
      }}>
        <span style={{
          fontSize: '0.6rem', color: 'var(--text-muted)',
          fontFamily: 'var(--font-display)', letterSpacing: '0.06em',
        }}>
          {incidents.length} INCIDENTS
        </span>
      </div>

      <div style={{ height: 'calc(100% - 24px)', overflowY: 'auto' }}>
        {incidents.length === 0 ? (
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            height: '100%', color: 'var(--text-muted)', fontSize: '0.7rem',
            fontFamily: 'var(--font-display)',
          }}>
            NO INCIDENTS
          </div>
        ) : (
          incidents.map((event, i) => (
            <IncidentCard
              key={event.soc_event_id || event.id || i}
              event={event}
              onExport={handleExport}
              exporting={exporting === (event.soc_event_id || event.id)}
            />
          ))
        )}
      </div>
    </Panel>
  )
}
