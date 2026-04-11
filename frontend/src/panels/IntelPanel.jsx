/**
 * Intel Panel — IP intelligence enrichment data.
 *
 * - 18px cyan IP address
 * - 8px full-width score bars with gradient
 * - Colored badges (TOR/VPN/PROXY/DC)
 * - 2-column data grid (label left, data right)
 * - No empty dashes — "UNKNOWN" in muted color
 */
import Panel from './Panel'
import { PANELS } from '../engine/layoutEngine'
import { useThreatState } from '../engine/threatState'

function ScoreBar({ label, score }) {
  const pct = Math.min(100, Math.max(0, score))
  const color = score >= 90 ? 'var(--red)'
    : score >= 70 ? '#ff7c2a'
    : score >= 50 ? 'var(--amber)'
    : 'var(--cyan)'

  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{
        display: 'flex', justifyContent: 'space-between',
        alignItems: 'baseline', marginBottom: 4,
      }}>
        <span className="intel-grid-label">{label}</span>
        <span style={{
          fontFamily: 'var(--font-display)', fontSize: 18,
          fontWeight: 700, color,
          textShadow: score >= 70 ? `0 0 10px ${color}40` : 'none',
        }}>
          {score.toFixed(0)}
        </span>
      </div>
      <div className="intel-score-bar">
        <div
          className="intel-score-fill"
          style={{
            width: `${pct}%`,
            background: `linear-gradient(90deg, ${color}cc, ${color})`,
            boxShadow: `0 0 8px ${color}40`,
          }}
        />
      </div>
    </div>
  )
}

export default function IntelPanel() {
  const { events } = useThreatState()

  const latest = events.find(e => e.source_ip) || {}
  const intel = latest.threat_intel || {}
  const ip = latest.source_ip
  const threatScore = intel.threat_score ?? latest.risk_score ?? 0
  const abuseScore = intel.abuse_confidence_score ?? 0

  return (
    <Panel panelId={PANELS.INTEL} title="IP INTEL" icon="&#9673;" scanline>
      {!ip ? (
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          height: '100%', color: 'var(--text-muted)', fontSize: 14,
          fontFamily: 'var(--font-display)', letterSpacing: '2px',
        }}>
          NO IP DATA
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {/* IP header */}
          <div className="intel-ip">{ip}</div>

          {/* Score bars */}
          <ScoreBar label="Threat Score" score={threatScore} />
          <ScoreBar label="Abuse Confidence" score={abuseScore} />

          {/* Anonymization badges */}
          <div className="intel-badges">
            {[
              { key: 'TOR', active: intel.is_tor || latest.ip_is_tor },
              { key: 'VPN', active: intel.is_vpn || latest.ip_is_vpn },
              { key: 'PROXY', active: intel.is_proxy || latest.ip_is_proxy },
              { key: 'DC', active: intel.is_datacenter || latest.ip_is_datacenter },
            ].map(f => (
              <span key={f.key} className={`intel-badge ${f.active ? 'intel-badge-active' : 'intel-badge-inactive'}`}>
                {f.key}
              </span>
            ))}
          </div>

          {/* Data grid */}
          <div className="intel-grid" style={{ marginTop: 8 }}>
            <span className="intel-grid-label">Country</span>
            <span className="intel-grid-value">
              {intel.geo?.country_name || latest.source_country || <span style={{ color: 'var(--text-muted)' }}>UNKNOWN</span>}
            </span>

            <span className="intel-grid-label">City</span>
            <span className="intel-grid-value">
              {intel.geo?.city || <span style={{ color: 'var(--text-muted)' }}>UNKNOWN</span>}
            </span>

            <span className="intel-grid-label">ASN</span>
            <span className="intel-grid-value">
              {intel.geo?.asn || latest.source_asn || <span style={{ color: 'var(--text-muted)' }}>UNKNOWN</span>}
            </span>

            <span className="intel-grid-label">ISP</span>
            <span className="intel-grid-value">
              {intel.geo?.isp || <span style={{ color: 'var(--text-muted)' }}>UNKNOWN</span>}
            </span>

            {intel.vt_malicious !== undefined && (
              <>
                <span className="intel-grid-label">VT Malicious</span>
                <span className="intel-grid-value" style={{
                  color: intel.vt_malicious > 0 ? 'var(--red)' : 'var(--green)',
                }}>
                  {intel.vt_malicious}
                </span>
              </>
            )}
          </div>
        </div>
      )}
    </Panel>
  )
}
