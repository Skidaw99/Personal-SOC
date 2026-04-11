/**
 * Threat Actor Panel — active threat actor profile.
 *
 * Large readable text, clear data hierarchy,
 * colored flags, known IPs list.
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
    <span className={`intel-badge ${active ? 'intel-badge-active' : 'intel-badge-inactive'}`}>
      {active && <span style={{
        width: 5, height: 5, borderRadius: '50%',
        background: 'var(--red)', marginRight: 4, display: 'inline-block',
      }} />}
      {label}
    </span>
  )
}

function DataRow({ label, value, color }) {
  return (
    <div className="intel-grid" style={{ marginBottom: 2 }}>
      <span className="intel-grid-label">{label}</span>
      <span className="intel-grid-value" style={{ color: color || 'var(--text-primary)' }}>
        {value || 'UNKNOWN'}
      </span>
    </div>
  )
}

export default function ThreatActorPanel() {
  const { activeActor } = useThreatState()
  const actor = activeActor || {}
  const level = actor.threat_level || 'low'
  const lc = LEVEL_COLORS[level] || 'var(--text-muted)'

  return (
    <Panel panelId={PANELS.ACTOR} title="THREAT ACTOR" icon="&#9670;">
      {!activeActor ? (
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          height: '100%', color: 'var(--text-muted)', fontSize: 14,
          fontFamily: 'var(--font-display)', letterSpacing: '2px',
        }}>
          NO ACTIVE ACTOR
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {/* Identity */}
          <div>
            <div style={{
              fontFamily: 'var(--font-display)', fontSize: 20, fontWeight: 700,
              color: lc, letterSpacing: '2px',
              textShadow: `0 0 16px ${lc}40`,
            }}>
              {actor.display_name || 'UNKNOWN'}
            </div>
          </div>

          {/* Threat level badge */}
          <span style={{
            alignSelf: 'flex-start',
            padding: '4px 14px',
            borderRadius: 4,
            background: `${lc}18`,
            border: `1px solid ${lc}40`,
            fontFamily: 'var(--font-display)',
            fontSize: 11, fontWeight: 600, letterSpacing: '2px',
            color: lc, textTransform: 'uppercase',
          }}>
            {level}
          </span>

          {/* Data rows */}
          <div style={{ marginTop: 4 }}>
            <DataRow label="Events" value={actor.total_events || 0} />
            <DataRow label="Status" value={(actor.status || 'active').toUpperCase()} />
            {actor.known_countries?.length > 0 && (
              <DataRow label="Countries" value={actor.known_countries.join(', ')} />
            )}
            {actor.platforms_targeted?.length > 0 && (
              <DataRow label="Platforms" value={actor.platforms_targeted.join(', ')} />
            )}
            {actor.attack_categories?.length > 0 && (
              <DataRow label="TTPs" value={actor.attack_categories.join(', ')} />
            )}
          </div>

          {/* Behavioral flags */}
          <div className="intel-badges">
            <Flag label="TOR" active={actor.is_tor} />
            <Flag label="VPN" active={actor.is_vpn} />
            <Flag label="BOT" active={actor.uses_automation} />
            <Flag label="X-PLAT" active={(actor.platforms_targeted?.length || 0) > 1} />
          </div>

          {/* Known IPs */}
          {actor.known_ips?.length > 0 && (
            <div>
              <div style={{
                fontFamily: 'var(--font-display)', fontSize: 11,
                letterSpacing: '2px', color: 'var(--text-muted)',
                textTransform: 'uppercase', marginBottom: 6,
              }}>
                Known IPs ({actor.known_ips.length})
              </div>
              {actor.known_ips.slice(0, 6).map(ip => (
                <div key={ip} style={{
                  fontFamily: 'var(--font-mono)', fontSize: 13,
                  color: 'var(--cyan)', padding: '2px 0',
                }}>
                  {ip}
                </div>
              ))}
              {actor.known_ips.length > 6 && (
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                  +{actor.known_ips.length - 6} more
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </Panel>
  )
}
