/**
 * Live Feed Panel — real-time WebSocket event stream.
 *
 * Shows incoming security events as a scrolling feed.
 * Each event shows: timestamp, type, IP, severity, risk score.
 * New events animate in from the top.
 */
import { useRef, useEffect } from 'react'
import Panel from './Panel'
import { PANELS } from '../engine/layoutEngine'
import { useThreatState } from '../engine/threatState'

const SEVERITY_COLORS = {
  critical: 'var(--red)',
  high: '#ff7c2a',
  medium: 'var(--amber)',
  low: 'var(--cyan)',
  info: 'var(--text-muted)',
}

function riskColor(score) {
  if (score >= 90) return 'var(--red)'
  if (score >= 70) return '#ff7c2a'
  if (score >= 50) return 'var(--amber)'
  return 'var(--cyan)'
}

function EventCard({ event, isNew }) {
  const severity = event.severity || 'medium'
  const risk = event.risk_score ?? event.threat_score ?? 0
  const eventType = (event.event_type || 'unknown').replace(/_/g, ' ')
  const time = event.occurred_at
    ? new Date(event.occurred_at).toLocaleTimeString('en-GB', { hour12: false })
    : new Date().toLocaleTimeString('en-GB', { hour12: false })

  return (
    <div
      className={isNew ? 'fade-in' : ''}
      style={{
        padding: '10px 12px',
        borderBottom: '1px solid var(--border)',
        display: 'flex',
        flexDirection: 'column',
        gap: 4,
        transition: 'background 200ms',
        cursor: 'default',
      }}
      onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-panel-hover)'}
      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{
          fontFamily: 'var(--font-display)',
          fontSize: '0.65rem',
          textTransform: 'uppercase',
          letterSpacing: '0.05em',
          color: SEVERITY_COLORS[severity] || 'var(--text-secondary)',
        }}>
          {eventType}
        </span>
        <span style={{
          fontSize: '0.7rem',
          color: riskColor(risk),
          fontWeight: 600,
        }}>
          {risk.toFixed(0)}
        </span>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
          {event.source_ip || '—'}
        </span>
        <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
          {time}
        </span>
      </div>

      {event.actor_display_name && (
        <div style={{
          fontSize: '0.65rem',
          color: 'var(--amber)',
          fontFamily: 'var(--font-display)',
          letterSpacing: '0.04em',
        }}>
          ▸ {event.actor_display_name}
        </div>
      )}
    </div>
  )
}

export default function LiveFeedPanel() {
  const { events, eventCount } = useThreatState()
  const scrollRef = useRef(null)

  // Auto-scroll to top when new events arrive
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = 0
    }
  }, [eventCount])

  return (
    <Panel panelId={PANELS.FEED} title="LIVE FEED" icon="⚡" scanline>
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: 8,
        padding: '0 2px',
      }}>
        <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontFamily: 'var(--font-display)' }}>
          {eventCount} EVENTS
        </span>
        <span style={{
          fontSize: '0.6rem',
          color: events.length > 0 ? 'var(--green)' : 'var(--text-muted)',
        }}>
          ● LIVE
        </span>
      </div>

      <div
        ref={scrollRef}
        style={{
          height: 'calc(100% - 28px)',
          overflowY: 'auto',
          overflowX: 'hidden',
        }}
      >
        {events.length === 0 ? (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            height: '100%',
            color: 'var(--text-muted)',
            fontSize: '0.75rem',
            fontFamily: 'var(--font-display)',
          }}>
            AWAITING EVENTS
          </div>
        ) : (
          events.map((event, i) => (
            <EventCard
              key={event.soc_event_id || event.id || `ev-${eventCount - i}`}
              event={event}
              isNew={i === 0}
            />
          ))
        )}
      </div>
    </Panel>
  )
}
