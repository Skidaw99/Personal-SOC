/**
 * SOC Cyber Operations Center — App Shell
 *
 * Context-Driven Adaptive UI.
 * No sidebar. No tabs. No navigation.
 * The entire layout is driven by the threat state machine.
 */
import { ThreatStateProvider, useThreatState, THREAT_STATES } from './engine/threatState'
import { useSOCWebSocket } from './hooks/useSOCWebSocket'
import ParticleGrid from './effects/ParticleGrid'
import AlertAudio from './effects/AlertAudio'
import GlobePanel from './panels/GlobePanel'
import LiveFeedPanel from './panels/LiveFeedPanel'
import ThreatActorPanel from './panels/ThreatActorPanel'
import IntelPanel from './panels/IntelPanel'
import CopilotPanel from './panels/CopilotPanel'
import EvidencePanel from './panels/EvidencePanel'

// ── Status bar (top of viewport) ────────────────────────────────────────────

function StatusBar() {
  const { current, eventCount, connected } = useStatusData()

  const stateColors = {
    CALM: 'var(--cyan)',
    ELEVATED: 'var(--amber)',
    ACTIVE: '#ff7c2a',
    CRITICAL: 'var(--red)',
  }

  const color = stateColors[current] || 'var(--text-muted)'

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      height: 32,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 20px',
      background: 'rgba(2, 4, 8, 0.8)',
      backdropFilter: 'blur(12px)',
      borderBottom: `1px solid ${current === 'CRITICAL' ? 'var(--border-danger)' : 'var(--border)'}`,
      zIndex: 100,
      fontFamily: 'var(--font-display)',
      fontSize: '0.6rem',
      letterSpacing: '0.12em',
    }}>
      {/* Left: system name */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{ color: 'var(--text-secondary)' }}>SOC</span>
        <span style={{ color: 'var(--text-muted)' }}>CYBER OPS CENTER</span>
      </div>

      {/* Center: threat state indicator */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
      }}>
        <span style={{
          width: 6, height: 6, borderRadius: '50%',
          background: color,
          boxShadow: `0 0 8px ${color}`,
          animation: current === 'CRITICAL' ? 'critical-pulse 1s ease infinite' : 'none',
        }} />
        <span style={{
          color,
          fontWeight: 700,
          textShadow: current === 'CRITICAL' ? `0 0 10px ${color}40` : 'none',
        }}>
          {current}
        </span>
      </div>

      {/* Right: connection status + event count */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.65rem' }}>
          {eventCount} events
        </span>
        <span style={{
          display: 'flex', alignItems: 'center', gap: 4,
          color: connected ? 'var(--green)' : 'var(--red)',
          fontSize: '0.55rem',
        }}>
          <span style={{
            width: 5, height: 5, borderRadius: '50%',
            background: connected ? 'var(--green)' : 'var(--red)',
          }} />
          {connected ? 'CONNECTED' : 'OFFLINE'}
        </span>
      </div>
    </div>
  )
}

function useStatusData() {
  const state = useThreatState()
  // connected comes from websocket, we'll pass it through
  return { ...state, connected: true }
}

// ── Threat state debug controls (dev only) ──────────────────────────────────

function DevControls() {
  const { current, setThreatState, processEvent } = useThreatState()

  function injectEvent(riskScore, eventType = 'brute_force') {
    processEvent({
      soc_event_id: crypto.randomUUID(),
      event_type: eventType,
      risk_score: riskScore,
      severity: riskScore >= 90 ? 'critical' : riskScore >= 70 ? 'high' : riskScore >= 50 ? 'medium' : 'low',
      source_ip: `${Math.floor(Math.random() * 223 + 1)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      source_country: ['DE', 'RU', 'CN', 'NL', 'US'][Math.floor(Math.random() * 5)],
      occurred_at: new Date().toISOString(),
      actor_display_name: riskScore >= 70 ? `TOR-BF-${Math.random().toString(16).slice(2, 6).toUpperCase()}` : undefined,
      actor_threat_level: riskScore >= 90 ? 'critical' : riskScore >= 70 ? 'high' : 'medium',
      actor: riskScore >= 70 ? {
        total_events: Math.floor(Math.random() * 100),
        known_ips: ['185.220.101.42', '185.220.101.43'],
        known_countries: ['DE', 'NL'],
        is_tor: true,
        uses_automation: riskScore >= 80,
        platforms_targeted: ['ssh', 'web'],
        attack_categories: [eventType],
      } : undefined,
    })
  }

  return (
    <div style={{
      position: 'fixed',
      bottom: 8,
      left: '50%',
      transform: 'translateX(-50%)',
      display: 'flex',
      gap: 4,
      zIndex: 200,
      padding: '4px 8px',
      background: 'rgba(2, 4, 8, 0.9)',
      border: '1px solid var(--border)',
      borderRadius: 8,
      backdropFilter: 'blur(12px)',
    }}>
      {Object.values(THREAT_STATES).map(state => (
        <button
          key={state}
          onClick={() => setThreatState(state)}
          style={{
            padding: '3px 8px',
            background: current === state ? 'var(--cyan-dim)' : 'transparent',
            border: `1px solid ${current === state ? 'var(--border-active)' : 'var(--border)'}`,
            borderRadius: 4,
            color: current === state ? 'var(--cyan)' : 'var(--text-muted)',
            fontFamily: 'var(--font-display)',
            fontSize: '0.5rem',
            letterSpacing: '0.08em',
          }}
        >
          {state}
        </button>
      ))}
      <div style={{ width: 1, background: 'var(--border)', margin: '0 4px' }} />
      <button
        onClick={() => injectEvent(30)}
        style={devBtnStyle}
        title="Low risk event"
      >
        +LOW
      </button>
      <button
        onClick={() => injectEvent(60)}
        style={devBtnStyle}
        title="Medium risk event"
      >
        +MED
      </button>
      <button
        onClick={() => injectEvent(80)}
        style={devBtnStyle}
        title="High risk event"
      >
        +HIGH
      </button>
      <button
        onClick={() => injectEvent(95, 'account_takeover')}
        style={{ ...devBtnStyle, color: 'var(--red)', borderColor: 'var(--border-danger)' }}
        title="Critical account takeover"
      >
        +CRIT
      </button>
    </div>
  )
}

const devBtnStyle = {
  padding: '3px 6px',
  background: 'transparent',
  border: '1px solid var(--border)',
  borderRadius: 4,
  color: 'var(--text-muted)',
  fontFamily: 'var(--font-mono)',
  fontSize: '0.5rem',
}

// ── Main viewport ───────────────────────────────────────────────────────────

function CyberOpsCenter() {
  const { stateClass, isCritical } = useThreatState()

  return (
    <div
      className={`${stateClass} ${isCritical ? 'critical-border' : ''}`}
      style={{
        width: '100vw',
        height: '100vh',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Background effects */}
      <ParticleGrid />

      {/* Status bar */}
      <StatusBar />

      {/* Audio alert (invisible) */}
      <AlertAudio />

      {/* All floating panels — no navigation, always present */}
      <GlobePanel />
      <LiveFeedPanel />
      <ThreatActorPanel />
      <IntelPanel />
      <CopilotPanel />
      <EvidencePanel />

      {/* Dev controls — remove in production */}
      <DevControls />
    </div>
  )
}

// ── App root ────────────────────────────────────────────────────────────────

export default function App() {
  return (
    <ThreatStateProvider>
      <CyberOpsCenter />
    </ThreatStateProvider>
  )
}
