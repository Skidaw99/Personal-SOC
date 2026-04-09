/**
 * Threat Actor Panel — active threat actor profile card.
 *
 * Shows the currently foregrounded actor with:
 * - Identity and threat level
 * - Known IPs, countries, platforms
 * - Behavioral flags (TOR, VPN, automation)
 * - Activity timeline sparkline
 */
import Panel from './Panel'
import { PANELS } from '../engine/layoutEngine'
import { useThreatState } from '../engine/threatState'

const LEVEL_COLORS = {
  critical: 'var(--red)',
  high: '#ff7c2a',
  medium: 'var(--amber)',
  low: 'var(--cyan)',
}

function Flag({ label, active }) {
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: 4,
      padding: '2px 8px',
      borderRadius: 4,
      fontSize: '0.6rem',
      fontFamily: 'var(--font-display)',
      letterSpacing: '0.06em',
      background: active ? 'var(--cyan-dim)' : 'transparent',
      border: `1px solid ${active ? 'var(--border-active)' : 'var(--border)'}`,
      color: active ? 'var(--cyan)' : 'var(--text-muted)',
      textTransform: 'uppercase',
    }}>
      {active && <span style={{ width: 4, height: 4, borderRadius: '50%', background: 'var(--cyan)' }} />}
      {label}
    </span>
  )
}

function DataRow({ label, value, color }) {
  return (
    <div style={{
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      padding: '4px 0',
      borderBottom: '1px solid rgba(255,255,255,0.03)',
    }}>
      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-display)', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
        {label}
      </span>
      <span style={{ fontSize: '0.75rem', color: color || 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
        {value}
      </span>
    </div>
  )
}

export default function ThreatActorPanel() {
  const { activeActor } = useThreatState()

  const actor = activeActor || {}
  const level = actor.threat_level || 'low'
  const levelColor = LEVEL_COLORS[level] || 'var(--text-muted)'

  return (
    <Panel panelId={PANELS.ACTOR} title="THREAT ACTOR" icon="👤">
      {!activeActor ? (
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          height: '100%', color: 'var(--text-muted)', fontSize: '0.7rem',
          fontFamily: 'var(--font-display)',
        }}>
          NO ACTIVE ACTOR
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {/* Identity header */}
          <div style={{ marginBottom: 4 }}>
            <div style={{
              fontFamily: 'var(--font-display)',
              fontSize: '1rem',
              fontWeight: 700,
              color: levelColor,
              letterSpacing: '0.05em',
              textShadow: `0 0 12px ${levelColor}40`,
            }}>
              {actor.display_name || 'UNKNOWN'}
            </div>
            {actor.alias && (
              <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: 2 }}>
                aka "{actor.alias}"
              </div>
            )}
          </div>

          {/* Threat level badge */}
          <div style={{
            display: 'inline-flex',
            alignSelf: 'flex-start',
            padding: '3px 10px',
            borderRadius: 4,
            background: `${levelColor}18`,
            border: `1px solid ${levelColor}40`,
            fontFamily: 'var(--font-display)',
            fontSize: '0.6rem',
            fontWeight: 600,
            color: levelColor,
            textTransform: 'uppercase',
            letterSpacing: '0.1em',
          }}>
            {level}
          </div>

          {/* Data rows */}
          <div style={{ marginTop: 4 }}>
            <DataRow label="Events" value={actor.total_events || 0} />
            <DataRow label="Confidence" value={`${(actor.confidence_score || 0).toFixed(0)}%`} />
            <DataRow label="Status" value={(actor.status || 'unknown').toUpperCase()} />
            {actor.known_countries?.length > 0 && (
              <DataRow label="Countries" value={actor.known_countries.join(', ')} />
            )}
            {actor.platforms_targeted?.length > 0 && (
              <DataRow label="Platforms" value={actor.platforms_targeted.join(', ')} />
            )}
          </div>

          {/* Behavioral flags */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
            <Flag label="TOR" active={actor.is_tor} />
            <Flag label="VPN" active={actor.is_vpn} />
            <Flag label="BOT" active={actor.uses_automation} />
            <Flag label="X-PLAT" active={actor.is_cross_platform} />
          </div>

          {/* Known IPs preview */}
          {actor.known_ips?.length > 0 && (
            <div style={{ marginTop: 6 }}>
              <div style={{
                fontSize: '0.6rem', color: 'var(--text-muted)',
                fontFamily: 'var(--font-display)', letterSpacing: '0.06em',
                textTransform: 'uppercase', marginBottom: 4,
              }}>
                Known IPs ({actor.known_ips.length})
              </div>
              {actor.known_ips.slice(0, 5).map(ip => (
                <div key={ip} style={{
                  fontSize: '0.7rem', color: 'var(--cyan)',
                  fontFamily: 'var(--font-mono)', padding: '1px 0',
                }}>
                  {ip}
                </div>
              ))}
              {actor.known_ips.length > 5 && (
                <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)' }}>
                  +{actor.known_ips.length - 5} more
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </Panel>
  )
}
