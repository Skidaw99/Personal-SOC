/**
 * SOC Screen — wrapper for the existing Cyber Operations Center.
 *
 * - ThreatStateProvider active only on this screen
 * - WebSocket activated only when this screen is mounted
 * - Adds with-nav CSS class for NavBar offset
 */
import { ThreatStateProvider, useThreatState, THREAT_STATES } from '../engine/threatState'
import { useSOCWebSocket } from '../hooks/useSOCWebSocket'
import ParticleGrid from '../effects/ParticleGrid'
import AlertAudio from '../effects/AlertAudio'
import GlobePanel from '../panels/GlobePanel'
import LiveFeedPanel from '../panels/LiveFeedPanel'
import ThreatActorPanel from '../panels/ThreatActorPanel'
import IntelPanel from '../panels/IntelPanel'
import CopilotPanel from '../panels/CopilotPanel'

// ── Critical banner (SOC-specific, inline) ──────────────────────────────────

function SOCCriticalBanner() {
  const { activeIncident } = useThreatState()
  if (!activeIncident) return null

  const risk = activeIncident.risk_score ?? 0
  const actor = activeIncident.actor_display_name || 'UNKNOWN'
  const type = (activeIncident.event_type || 'threat').replace(/_/g, ' ').toUpperCase()

  return (
    <div className="critical-banner">
      <div className="critical-banner-inner">
        <span className="critical-banner-icon">&#9888;</span>
        <span className="critical-banner-text">CRITICAL THREAT</span>
        <span className="critical-banner-sep">|</span>
        <span className="critical-banner-detail">{type}</span>
        <span className="critical-banner-sep">|</span>
        <span className="critical-banner-actor">{actor}</span>
        <span className="critical-banner-sep">|</span>
        <span className="critical-banner-risk">{risk.toFixed(0)}</span>
      </div>
    </div>
  )
}

// ── Status bar ──────────────────────────────────────────────────────────────

function StatusBar({ connected }) {
  const { current, eventCount } = useThreatState()

  const stateColors = {
    CALM: 'var(--cyan)',
    ELEVATED: 'var(--amber)',
    ACTIVE: '#ff7c2a',
    CRITICAL: 'var(--red)',
  }
  const color = stateColors[current] || 'var(--text-muted)'

  return (
    <div className="status-bar">
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{ color: 'var(--text-secondary)' }}>SOC</span>
        <span style={{ color: 'var(--text-muted)' }}>CYBER OPS CENTER</span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{
          width: 6, height: 6, borderRadius: '50%',
          background: color,
          boxShadow: `0 0 8px ${color}`,
          animation: current === 'CRITICAL' ? 'pulse-dot 1s ease infinite' : 'none',
        }} />
        <span style={{ color, fontWeight: 700 }}>{current}</span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
          {eventCount} events
        </span>
        <span style={{
          display: 'flex', alignItems: 'center', gap: 4,
          color: connected ? 'var(--green)' : 'var(--red)',
          fontSize: 10,
        }}>
          <span style={{
            width: 5, height: 5, borderRadius: '50%',
            background: connected ? 'var(--green)' : 'var(--red)',
            animation: connected ? 'live-blink 2s ease infinite' : 'none',
          }} />
          {connected ? 'LIVE' : 'OFFLINE'}
        </span>
      </div>
    </div>
  )
}

// ── HUD chips (CALM only) ───────────────────────────────────────────────────

function HudChips() {
  const { eventCount, events, activeActor } = useThreatState()

  const actorCount = new Set(events.filter(e => e.actor_display_name).map(e => e.actor_display_name)).size
  const avgRisk = events.length > 0
    ? (events.reduce((s, e) => s + (e.risk_score ?? 0), 0) / events.length).toFixed(0)
    : '0'

  return (
    <div className="hud-chips">
      <div className="hud-chip hud-chip-tl">
        <div className="hud-chip-value">{eventCount}</div>
        <div className="hud-chip-label">Events Today</div>
      </div>
      <div className="hud-chip hud-chip-tr">
        <div className="hud-chip-value">{actorCount}</div>
        <div className="hud-chip-label">Active Actors</div>
      </div>
      <div className="hud-chip hud-chip-bl">
        <div className="hud-chip-value">{avgRisk}</div>
        <div className="hud-chip-label">Avg Risk</div>
      </div>
      <div className="hud-chip hud-chip-br">
        <div className="hud-chip-value" style={{ color: 'var(--green)' }}>ONLINE</div>
        <div className="hud-chip-label">System Status</div>
      </div>
    </div>
  )
}

// ── Ticker bar ──────────────────────────────────────────────────────────────

function TickerBar() {
  const { events } = useThreatState()
  const recent = events.slice(0, 5)

  function riskColor(s) {
    if (s >= 90) return 'var(--red)'
    if (s >= 70) return '#ff7c2a'
    if (s >= 50) return 'var(--amber)'
    return 'var(--cyan)'
  }

  return (
    <div className="ticker-bar">
      <span className="ticker-label">Latest</span>
      {recent.length === 0 ? (
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>No events</span>
      ) : (
        recent.map((e, i) => {
          const risk = e.risk_score ?? 0
          const type = (e.event_type || 'unknown').replace(/_/g, ' ')
          const time = e.occurred_at
            ? new Date(e.occurred_at).toLocaleTimeString('en-GB', { hour12: false })
            : ''
          return (
            <div className="ticker-event" key={e.soc_event_id || i}>
              <span className="ticker-event-type" style={{ color: riskColor(risk) }}>{type}</span>
              <span className="ticker-event-ip">{e.source_ip || '—'}</span>
              <span className="ticker-event-risk" style={{ color: riskColor(risk) }}>{risk.toFixed(0)}</span>
              <span className="ticker-event-time">{time}</span>
            </div>
          )
        })
      )}
    </div>
  )
}

// ── Dev controls ────────────────────────────────────────────────────────────

function DevControls() {
  const { current, setThreatState, processEvent } = useThreatState()

  function inject(riskScore, eventType = 'brute_force') {
    const countries = [
      { c: 'RU', lat: 55.75, lng: 37.62 },
      { c: 'CN', lat: 39.9, lng: 116.4 },
      { c: 'DE', lat: 52.52, lng: 13.4 },
      { c: 'US', lat: 40.71, lng: -74.0 },
      { c: 'BR', lat: -23.55, lng: -46.63 },
      { c: 'IR', lat: 35.69, lng: 51.39 },
      { c: 'KP', lat: 39.03, lng: 125.75 },
    ]
    const geo = countries[Math.floor(Math.random() * countries.length)]
    processEvent({
      soc_event_id: crypto.randomUUID(),
      event_type: eventType,
      risk_score: riskScore,
      severity: riskScore >= 90 ? 'critical' : riskScore >= 70 ? 'high' : riskScore >= 50 ? 'medium' : 'low',
      source_ip: `${Math.floor(Math.random()*223+1)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
      source_country: geo.c,
      source_latitude: geo.lat + (Math.random() - 0.5) * 10,
      source_longitude: geo.lng + (Math.random() - 0.5) * 10,
      occurred_at: new Date().toISOString(),
      actor_display_name: riskScore >= 70 ? `TOR-BF-${Math.random().toString(16).slice(2,6).toUpperCase()}` : undefined,
      actor_threat_level: riskScore >= 90 ? 'critical' : riskScore >= 70 ? 'high' : 'medium',
      actor: riskScore >= 70 ? {
        total_events: Math.floor(Math.random()*100),
        known_ips: ['185.220.101.42','185.220.101.43','45.33.32.156'],
        known_countries: ['DE','NL','RU'],
        is_tor: true,
        uses_automation: riskScore >= 80,
        platforms_targeted: ['ssh','web','api'],
        attack_categories: [eventType],
      } : undefined,
      threat_intel: riskScore >= 50 ? {
        threat_score: riskScore * 0.9,
        abuse_confidence_score: Math.min(100, riskScore + 10),
        is_tor: riskScore >= 80,
        is_vpn: riskScore >= 60 && riskScore < 80,
        is_proxy: false,
        is_datacenter: riskScore >= 70,
        geo: { country_name: geo.c, city: 'Unknown', asn: 'AS' + Math.floor(Math.random()*60000), isp: 'Unknown ISP' },
        vt_malicious: riskScore >= 70 ? Math.floor(Math.random()*10) : 0,
      } : undefined,
    })
  }

  const btnBase = {
    padding: '3px 8px',
    background: 'transparent',
    border: '1px solid var(--border)',
    borderRadius: 4,
    fontFamily: 'var(--font-mono)',
    fontSize: 10,
    letterSpacing: '0.5px',
    cursor: 'pointer',
  }

  return (
    <div style={{
      position: 'fixed', bottom: 8, left: '50%', transform: 'translateX(-50%)',
      display: 'flex', gap: 4, zIndex: 300,
      padding: '4px 8px', background: 'rgba(2,4,8,0.92)',
      border: '1px solid var(--border)', borderRadius: 8, backdropFilter: 'blur(12px)',
    }}>
      {Object.values(THREAT_STATES).map(s => (
        <button key={s} onClick={() => setThreatState(s)} style={{
          ...btnBase,
          background: current === s ? 'var(--cyan-dim)' : 'transparent',
          borderColor: current === s ? 'var(--border-active)' : 'var(--border)',
          color: current === s ? 'var(--cyan)' : 'var(--text-muted)',
          fontFamily: 'var(--font-display)', fontSize: 9, letterSpacing: '1px',
        }}>{s}</button>
      ))}
      <div style={{ width: 1, background: 'var(--border)', margin: '0 4px' }} />
      <button onClick={() => inject(30)} style={{ ...btnBase, color: 'var(--cyan)' }}>+LOW</button>
      <button onClick={() => inject(60)} style={{ ...btnBase, color: 'var(--amber)' }}>+MED</button>
      <button onClick={() => inject(80)} style={{ ...btnBase, color: '#ff7c2a' }}>+HIGH</button>
      <button onClick={() => inject(95, 'account_takeover')} style={{ ...btnBase, color: 'var(--red)', borderColor: 'var(--border-danger)' }}>+CRIT</button>
    </div>
  )
}

// ── Main SOC viewport ───────────────────────────────────────────────────────

function CyberOpsCenter() {
  const { stateClass, isCritical } = useThreatState()
  const { connected } = useSOCWebSocket()

  return (
    <div className={`ops-center with-nav ${stateClass} ${isCritical ? 'critical-active' : ''}`}>
      <ParticleGrid />
      <SOCCriticalBanner />
      <StatusBar connected={connected} />
      <HudChips />

      <GlobePanel />
      <LiveFeedPanel />
      <ThreatActorPanel />
      <IntelPanel />
      <CopilotPanel />

      <TickerBar />
      <AlertAudio />
      <DevControls />
    </div>
  )
}

// ── SOC Screen export ───────────────────────────────────────────────────────

export default function SOCScreen() {
  return (
    <ThreatStateProvider>
      <CyberOpsCenter />
    </ThreatStateProvider>
  )
}
