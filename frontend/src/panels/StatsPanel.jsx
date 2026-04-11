/**
 * Stats Panel — live counters, risk gauge, 24h alert sparkline.
 *
 * Replaces the Evidence panel with real-time operational metrics.
 * All data is derived from the threat state machine (no extra API calls).
 */
import { useMemo, useRef, useEffect } from 'react'
import Panel from './Panel'
import { PANELS } from '../engine/layoutEngine'
import { useThreatState } from '../engine/threatState'

// ── Circular risk gauge (SVG) ────────────────────────────────────────────────

function RiskGauge({ score }) {
  const radius = 38
  const stroke = 5
  const circumference = 2 * Math.PI * radius
  const pct = Math.min(100, Math.max(0, score))
  const offset = circumference - (pct / 100) * circumference

  const color = score >= 90 ? 'var(--red)'
    : score >= 70 ? '#ff8c00'
    : score >= 50 ? 'var(--amber)'
    : 'var(--cyan)'

  const glowFilter = score >= 70
    ? 'drop-shadow(0 0 6px rgba(255, 0, 64, 0.4))'
    : 'drop-shadow(0 0 6px rgba(0, 212, 255, 0.3))'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
      <svg width={96} height={96} viewBox="0 0 96 96" style={{ filter: glowFilter }}>
        {/* Background circle */}
        <circle
          cx="48" cy="48" r={radius}
          fill="none"
          stroke="rgba(255,255,255,0.06)"
          strokeWidth={stroke}
        />
        {/* Progress arc */}
        <circle
          cx="48" cy="48" r={radius}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 48 48)"
          style={{ transition: 'stroke-dashoffset 800ms ease, stroke 400ms ease' }}
        />
        {/* Center text */}
        <text
          x="48" y="44"
          textAnchor="middle"
          fill={color}
          fontSize="18"
          fontFamily="var(--font-display)"
          fontWeight="700"
        >
          {score.toFixed(0)}
        </text>
        <text
          x="48" y="58"
          textAnchor="middle"
          fill="rgba(255,255,255,0.35)"
          fontSize="7"
          fontFamily="var(--font-display)"
          letterSpacing="0.12em"
        >
          RISK SCORE
        </text>
      </svg>
    </div>
  )
}

// ── Sparkline (SVG) ──────────────────────────────────────────────────────────

function Sparkline({ data, color = 'var(--cyan)', height = 32, width = '100%' }) {
  if (!data || data.length < 2) {
    return (
      <div style={{
        height, display: 'flex', alignItems: 'center', justifyContent: 'center',
        color: 'var(--text-muted)', fontSize: '0.6rem', fontFamily: 'var(--font-display)',
      }}>
        COLLECTING DATA
      </div>
    )
  }

  const max = Math.max(...data, 1)
  const svgW = 200
  const svgH = height
  const padding = 2

  const points = data.map((v, i) => {
    const x = padding + (i / (data.length - 1)) * (svgW - padding * 2)
    const y = svgH - padding - ((v / max) * (svgH - padding * 2))
    return `${x},${y}`
  }).join(' ')

  // Area fill path
  const firstX = padding
  const lastX = padding + ((data.length - 1) / (data.length - 1)) * (svgW - padding * 2)
  const areaPath = `M ${firstX},${svgH} L ${points.split(' ').map(p => p).join(' L ')} L ${lastX},${svgH} Z`

  return (
    <svg
      viewBox={`0 0 ${svgW} ${svgH}`}
      preserveAspectRatio="none"
      style={{ width, height, display: 'block' }}
    >
      <defs>
        <linearGradient id="spark-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.15" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={areaPath} fill="url(#spark-fill)" />
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  )
}

// ── Counter card ─────────────────────────────────────────────────────────────

function Counter({ label, value, color = 'var(--text-primary)', sub }) {
  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      padding: '8px 4px',
      flex: 1,
      minWidth: 0,
    }}>
      <span style={{
        fontFamily: 'var(--font-display)',
        fontSize: '1.1rem',
        fontWeight: 700,
        color,
        lineHeight: 1,
        textShadow: `0 0 12px ${color}30`,
      }}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </span>
      <span style={{
        fontFamily: 'var(--font-display)',
        fontSize: '0.5rem',
        color: 'var(--text-muted)',
        letterSpacing: '0.1em',
        textTransform: 'uppercase',
        marginTop: 4,
        textAlign: 'center',
      }}>
        {label}
      </span>
      {sub && (
        <span style={{
          fontSize: '0.5rem',
          color: 'var(--text-muted)',
          marginTop: 1,
        }}>
          {sub}
        </span>
      )}
    </div>
  )
}

// ── Stats panel ──────────────────────────────────────────────────────────────

export default function StatsPanel() {
  const { events, eventCount, activeActor, activeIncident, current } = useThreatState()
  const sparklineRef = useRef([])
  const lastBucketRef = useRef(0)

  // Compute live stats from state
  const stats = useMemo(() => {
    const now = Date.now()
    const oneHourAgo = now - 3600_000

    const recentEvents = events.filter(e => {
      const t = e.occurred_at ? new Date(e.occurred_at).getTime() : now
      return t >= oneHourAgo
    })

    const alertCount = events.filter(e => (e.risk_score ?? 0) >= 50).length
    const criticalCount = events.filter(e => (e.risk_score ?? 0) >= 90).length

    // Unique actors seen
    const actors = new Set()
    events.forEach(e => {
      if (e.actor_display_name) actors.add(e.actor_display_name)
    })

    // Unique source IPs
    const ips = new Set()
    events.forEach(e => {
      if (e.source_ip) ips.add(e.source_ip)
    })

    // Average risk of recent events
    const avgRisk = events.length > 0
      ? events.reduce((sum, e) => sum + (e.risk_score ?? 0), 0) / events.length
      : 0

    // Peak risk
    const peakRisk = events.length > 0
      ? Math.max(...events.map(e => e.risk_score ?? 0))
      : 0

    return {
      totalEvents: eventCount,
      alerts: alertCount,
      criticals: criticalCount,
      actors: actors.size,
      uniqueIPs: ips.size,
      avgRisk,
      peakRisk,
      recentCount: recentEvents.length,
    }
  }, [events, eventCount])

  // Build sparkline data: count events in 5-minute buckets
  useEffect(() => {
    const now = Math.floor(Date.now() / 300_000) // 5-minute bucket
    if (now !== lastBucketRef.current) {
      lastBucketRef.current = now
      // Count events that just arrived
      const count = events.filter(e => {
        const t = e.occurred_at ? new Date(e.occurred_at).getTime() : Date.now()
        return Math.floor(t / 300_000) === now
      }).length
      sparklineRef.current = [...sparklineRef.current, count].slice(-48) // 4 hours of 5-min buckets
    }
  }, [events])

  // Also push a value when eventCount changes
  useEffect(() => {
    if (sparklineRef.current.length === 0) {
      sparklineRef.current = [0]
    }
    // Increment last bucket
    const newData = [...sparklineRef.current]
    newData[newData.length - 1] = (newData[newData.length - 1] || 0) + 1
    sparklineRef.current = newData
  }, [eventCount])

  const riskColor = stats.peakRisk >= 90 ? 'var(--red)'
    : stats.peakRisk >= 70 ? '#ff8c00'
    : stats.peakRisk >= 50 ? 'var(--amber)'
    : 'var(--cyan)'

  return (
    <Panel panelId={PANELS.STATS} title="STATS" icon="◆">
      <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: 10 }}>

        {/* Risk gauge */}
        <RiskGauge score={stats.peakRisk} />

        {/* Counters grid */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: 2,
          borderTop: '1px solid var(--border)',
          borderBottom: '1px solid var(--border)',
          padding: '6px 0',
        }}>
          <Counter label="Events" value={stats.totalEvents} color="var(--cyan)" />
          <Counter label="Alerts" value={stats.alerts} color="var(--amber)" />
          <Counter label="Critical" value={stats.criticals} color="var(--red)" />
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: 2,
          paddingBottom: 6,
          borderBottom: '1px solid var(--border)',
        }}>
          <Counter label="Actors" value={stats.actors} color="#ff8c00" />
          <Counter label="IPs" value={stats.uniqueIPs} color="var(--text-primary)" />
          <Counter label="Avg Risk" value={stats.avgRisk.toFixed(0)} color={riskColor} />
        </div>

        {/* Alert volume sparkline */}
        <div>
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: 4,
          }}>
            <span style={{
              fontSize: '0.55rem',
              color: 'var(--text-muted)',
              fontFamily: 'var(--font-display)',
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
            }}>
              Alert Volume
            </span>
            <span style={{
              fontSize: '0.55rem',
              color: 'var(--text-muted)',
            }}>
              {sparklineRef.current.length > 0
                ? `${sparklineRef.current.length * 5}min`
                : '—'}
            </span>
          </div>
          <Sparkline data={sparklineRef.current} color={riskColor} height={36} />
        </div>

        {/* Threat state indicator */}
        <div style={{
          marginTop: 'auto',
          padding: '8px 0 2px',
          borderTop: '1px solid var(--border)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}>
          <span style={{
            fontSize: '0.55rem',
            color: 'var(--text-muted)',
            fontFamily: 'var(--font-display)',
            letterSpacing: '0.08em',
          }}>
            THREATCON
          </span>
          <span style={{
            fontSize: '0.7rem',
            fontWeight: 700,
            fontFamily: 'var(--font-display)',
            color: current === 'CRITICAL' ? 'var(--red)'
              : current === 'ACTIVE' ? '#ff8c00'
              : current === 'ELEVATED' ? 'var(--amber)'
              : 'var(--cyan)',
            textShadow: current === 'CRITICAL'
              ? '0 0 10px var(--red-glow)' : 'none',
          }}>
            {current}
          </span>
        </div>
      </div>
    </Panel>
  )
}
