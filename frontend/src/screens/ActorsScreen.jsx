/**
 * Actors Screen — threat actor profiles.
 *
 * Actor card grid, detail view with attack timeline,
 * known IPs, FBI Brief generator with download.
 */
import { useState, useEffect } from 'react'
import { api } from '../api'

const LEVEL_COLORS = {
  critical: 'var(--red)',
  high: '#ff7c2a',
  medium: 'var(--amber)',
  low: 'var(--cyan)',
}

function riskColor(s) {
  if (s >= 90) return 'var(--red)'
  if (s >= 70) return '#ff7c2a'
  if (s >= 50) return 'var(--amber)'
  return 'var(--cyan)'
}

function ActorCard({ actor, onClick }) {
  const lc = LEVEL_COLORS[actor.threat_level] || 'var(--text-muted)'

  return (
    <div className="actor-card" onClick={onClick}>
      <div className="actor-card-header">
        <span className="actor-card-name" style={{ color: lc }}>{actor.display_name}</span>
        <span className="actor-card-level" style={{ color: lc, borderColor: `${lc}60` }}>
          {actor.threat_level?.toUpperCase()}
        </span>
      </div>
      <div className="actor-card-stats">
        <span>{actor.event_count} events</span>
        <span>{actor.known_ips?.length || 0} IPs</span>
        <span>Score: {(actor.max_risk_score || 0).toFixed(0)}</span>
      </div>
      <div className="actor-card-ips">
        {(actor.known_ips || []).slice(0, 3).map(ip => (
          <span key={ip} className="actor-ip">{ip}</span>
        ))}
        {(actor.known_ips?.length || 0) > 3 && (
          <span className="text-muted text-sm">+{actor.known_ips.length - 3} more</span>
        )}
      </div>
      <div className="intel-badges" style={{ marginTop: 8 }}>
        {actor.known_countries?.map(c => (
          <span key={c} className="intel-badge intel-badge-active">{c}</span>
        ))}
        {actor.is_tor && <span className="intel-badge intel-badge-active">TOR</span>}
        {actor.is_vpn && <span className="intel-badge intel-badge-active">VPN</span>}
        {actor.uses_automation && <span className="intel-badge intel-badge-active">BOT</span>}
      </div>
      <div className="actor-card-footer">
        <span className="text-muted text-sm">
          Last seen: {actor.last_seen ? new Date(actor.last_seen).toLocaleString('en-GB', { hour12: false }) : 'unknown'}
        </span>
        <button className="btn btn-cyan btn-sm">VIEW DETAILS</button>
      </div>
    </div>
  )
}

function ActorDetail({ actorId, onBack }) {
  const [actor, setActor] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [briefText, setBriefText] = useState('')
  const [briefLoading, setBriefLoading] = useState(false)

  useEffect(() => {
    async function fetch() {
      try {
        const data = await api.getActor(actorId)
        setActor(data)
      } catch (err) {
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }
    fetch()
  }, [actorId])

  async function generateBrief() {
    if (!actor) return
    setBriefLoading(true)
    try {
      const result = await api.generateFBIBrief({
        case_reference: `SOC-${actor.display_name}-${Date.now()}`,
        incident_type: 'cyber_threat',
        risk_score: actor.max_risk_score || 80,
        actor_profile: {
          display_name: actor.display_name,
          threat_level: actor.threat_level,
          known_ips: actor.known_ips,
          known_countries: actor.known_countries,
          platforms: actor.platforms,
          event_count: actor.event_count,
        },
        involved_ips: (actor.known_ips || []).map(ip => ({ ip })),
        timeline: (actor.timeline || []).slice(0, 20).map(e => ({
          timestamp: e.occurred_at,
          event_type: e.event_type,
          source_ip: e.source_ip,
          risk_score: e.threat_score,
        })),
      })
      setBriefText(result.content || 'No brief generated.')
    } catch (err) {
      setBriefText(`Error: ${err.message}`)
    } finally {
      setBriefLoading(false)
    }
  }

  function downloadBrief() {
    if (!briefText) return
    const blob = new Blob([briefText], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `fbi-brief-${actor?.display_name || 'actor'}-${Date.now()}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  function copyBrief() {
    if (!briefText) return
    navigator.clipboard.writeText(briefText)
  }

  if (loading) return <div className="screen screen-center"><span className="loading-text">LOADING ACTOR...</span></div>
  if (error) return <div className="screen screen-center"><div className="error-card"><span className="error-text">{error}</span></div></div>
  if (!actor) return null

  const lc = LEVEL_COLORS[actor.threat_level] || 'var(--text-muted)'

  return (
    <div className="screen">
      {/* Header */}
      <div className="screen-header">
        <button className="btn btn-muted" onClick={onBack}>&#8592; BACK</button>
        <h2 className="screen-title" style={{ color: lc }}>{actor.display_name}</h2>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span className="actor-card-level" style={{ color: lc, borderColor: `${lc}60`, fontSize: 12, padding: '4px 12px' }}>
            {actor.threat_level?.toUpperCase()}
          </span>
          <button className="btn btn-cyan" onClick={generateBrief} disabled={briefLoading}>
            {briefLoading ? 'GENERATING...' : 'GENERATE FBI BRIEF'}
          </button>
        </div>
      </div>

      {/* Intelligence summary */}
      <div className="dashboard-section">
        <h3 className="section-title">INTELLIGENCE SUMMARY</h3>
        <div className="stat-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
          <div className="stat-card">
            <div className="stat-value" style={{ color: lc }}>{(actor.max_risk_score || 0).toFixed(0)}</div>
            <div className="stat-label">MAX RISK</div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{actor.event_count || 0}</div>
            <div className="stat-label">EVENTS</div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{actor.known_ips?.length || 0}</div>
            <div className="stat-label">KNOWN IPS</div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{actor.known_countries?.length || 0}</div>
            <div className="stat-label">COUNTRIES</div>
          </div>
        </div>
      </div>

      {/* Known IPs */}
      {actor.known_ips?.length > 0 && (
        <div className="dashboard-section">
          <h3 className="section-title">KNOWN IPS ({actor.known_ips.length})</h3>
          <div className="actor-ip-grid">
            {actor.known_ips.map(ip => (
              <span key={ip} className="actor-ip-tag">{ip}</span>
            ))}
          </div>
        </div>
      )}

      {/* Countries + Platforms */}
      <div className="dashboard-section" style={{ display: 'flex', gap: 24 }}>
        {actor.known_countries?.length > 0 && (
          <div>
            <h3 className="section-title">COUNTRIES</h3>
            <div className="intel-badges">
              {actor.known_countries.map(c => <span key={c} className="intel-badge intel-badge-active">{c}</span>)}
            </div>
          </div>
        )}
        {actor.platforms?.length > 0 && (
          <div>
            <h3 className="section-title">PLATFORMS</h3>
            <div className="intel-badges">
              {actor.platforms.map(p => <span key={p} className="intel-badge intel-badge-active">{p.toUpperCase()}</span>)}
            </div>
          </div>
        )}
      </div>

      {/* Attack timeline */}
      {actor.timeline?.length > 0 && (
        <div className="dashboard-section">
          <h3 className="section-title">ATTACK TIMELINE ({actor.timeline.length})</h3>
          <div className="actor-timeline">
            {actor.timeline.map((event, i) => (
              <div key={event.id || i} className="timeline-event">
                <div className="timeline-dot" style={{ background: riskColor(event.threat_score) }} />
                <div className="timeline-line" />
                <div className="timeline-content">
                  <span className="timeline-time">
                    {event.occurred_at ? new Date(event.occurred_at).toLocaleString('en-GB', { hour12: false }) : ''}
                  </span>
                  <span className="timeline-type" style={{ color: riskColor(event.threat_score) }}>
                    {(event.event_type || 'unknown').replace(/_/g, ' ').toUpperCase()}
                  </span>
                  <span className="timeline-ip">{event.source_ip || ''}</span>
                  <span className="timeline-score" style={{ color: riskColor(event.threat_score) }}>
                    {(event.threat_score || 0).toFixed(0)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* FBI Brief output */}
      {briefText && (
        <div className="dashboard-section">
          <h3 className="section-title">FBI BRIEF</h3>
          <textarea className="form-input form-textarea fbi-brief-output" value={briefText} readOnly rows={20} />
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <button className="btn btn-cyan" onClick={copyBrief}>COPY</button>
            <button className="btn btn-muted" onClick={downloadBrief}>DOWNLOAD .TXT</button>
          </div>
        </div>
      )}
    </div>
  )
}

export default function ActorsScreen() {
  const [actors, setActors] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [selectedId, setSelectedId] = useState(null)

  useEffect(() => {
    async function fetch() {
      try {
        const data = await api.getActors()
        setActors(data || [])
      } catch (err) {
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }
    fetch()
  }, [])

  if (selectedId) {
    return <ActorDetail actorId={selectedId} onBack={() => setSelectedId(null)} />
  }

  if (loading) return <div className="screen screen-center"><span className="loading-text">LOADING ACTORS...</span></div>

  return (
    <div className="screen">
      <h2 className="screen-title">THREAT ACTORS</h2>

      {error && <div className="error-card" style={{ marginBottom: 12 }}><span className="error-text">{error}</span></div>}

      {actors.length === 0 ? (
        <div className="empty-state">NO THREAT ACTORS DETECTED</div>
      ) : (
        <div className="actor-grid">
          {actors.map(actor => (
            <ActorCard key={actor.id} actor={actor} onClick={() => setSelectedId(actor.id)} />
          ))}
        </div>
      )}
    </div>
  )
}
