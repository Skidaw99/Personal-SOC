/**
 * Live Feed Panel — real-time event stream.
 *
 * Cards: 56px min, 3px left color border,
 * large risk scores, slide-in animation.
 */
import { useRef, useEffect } from 'react'
import Panel from './Panel'
import { PANELS } from '../engine/layoutEngine'
import { useThreatState } from '../engine/threatState'

function riskColor(s) {
  if (s >= 90) return 'var(--red)'
  if (s >= 70) return '#ff7c2a'
  if (s >= 50) return 'var(--amber)'
  return 'var(--cyan)'
}

function severityClass(s) {
  if (s === 'critical') return 'event-card-critical'
  if (s === 'high') return 'event-card-high'
  if (s === 'medium') return 'event-card-medium'
  return 'event-card-low'
}

function EventCard({ event, isNew }) {
  const severity = event.severity || 'medium'
  const risk = event.risk_score ?? 0
  const type = (event.event_type || 'unknown').replace(/_/g, ' ')
  const time = event.occurred_at
    ? new Date(event.occurred_at).toLocaleTimeString('en-GB', { hour12: false })
    : new Date().toLocaleTimeString('en-GB', { hour12: false })

  return (
    <div className={`event-card ${severityClass(severity)}`} style={isNew ? {} : { animation: 'none' }}>
      <div className="event-card-row">
        <span className="event-card-type" style={{ color: riskColor(risk) }}>
          {type}
        </span>
        <span className="event-card-risk" style={{ color: riskColor(risk) }}>
          {risk.toFixed(0)}
        </span>
      </div>
      <div className="event-card-row">
        <div className="event-card-meta">
          <span className="event-card-ip">{event.source_ip || '—'}</span>
          <span className="event-card-time">{time}</span>
          {event.source_country && (
            <span className="event-card-time">{event.source_country}</span>
          )}
        </div>
      </div>
      {event.actor_display_name && (
        <span className="event-card-actor">&#9654; {event.actor_display_name}</span>
      )}
    </div>
  )
}

export default function LiveFeedPanel() {
  const { events, eventCount, isCritical } = useThreatState()
  const scrollRef = useRef(null)

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = 0
  }, [eventCount])

  // In CRITICAL: show only critical events
  const displayEvents = isCritical
    ? events.filter(e => (e.risk_score ?? 0) >= 70)
    : events

  return (
    <Panel
      panelId={PANELS.FEED}
      title="LIVE FEED"
      icon="&#9889;"
      scanline
      status={
        <span style={{
          display: 'flex', alignItems: 'center', gap: 5,
          color: events.length > 0 ? 'var(--green)' : 'var(--text-muted)',
          fontSize: 10,
        }}>
          <span style={{
            width: 5, height: 5, borderRadius: '50%',
            background: events.length > 0 ? 'var(--green)' : 'var(--text-muted)',
            animation: events.length > 0 ? 'live-blink 1s step-end infinite' : 'none',
          }} />
          LIVE
        </span>
      }
    >
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        marginBottom: 8, padding: '0 2px',
      }}>
        <span style={{
          fontFamily: 'var(--font-display)', fontSize: 11,
          letterSpacing: '2px', color: 'var(--text-muted)',
        }}>
          {eventCount} EVENTS
        </span>
      </div>

      <div ref={scrollRef} style={{ height: 'calc(100% - 30px)', overflowY: 'auto', overflowX: 'hidden' }}>
        {displayEvents.length === 0 ? (
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            height: '100%', color: 'var(--text-muted)', fontSize: 14,
            fontFamily: 'var(--font-display)', letterSpacing: '2px',
          }}>
            AWAITING EVENTS
          </div>
        ) : (
          displayEvents.map((event, i) => (
            <EventCard
              key={event.soc_event_id || `ev-${eventCount - i}`}
              event={event}
              isNew={i === 0}
            />
          ))
        )}
      </div>
    </Panel>
  )
}
