/**
 * Intel Panel — IP intelligence enrichment data.
 *
 * Shows enrichment results for the most relevant IP:
 * - Threat score with visual gauge
 * - Geo data, ASN, ISP
 * - Anonymization flags (TOR/VPN/Proxy)
 * - AbuseIPDB, VirusTotal, Shodan summaries
 */
import { useState } from 'react'
import Panel from './Panel'
import { PANELS } from '../engine/layoutEngine'
import { useThreatState } from '../engine/threatState'

function ScoreGauge({ score, label }) {
  const color = score >= 90 ? 'var(--red)'
    : score >= 70 ? '#ff7c2a'
    : score >= 50 ? 'var(--amber)'
    : 'var(--cyan)'

  const pct = Math.min(100, Math.max(0, score))

  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
        <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)', fontFamily: 'var(--font-display)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          {label}
        </span>
        <span className={score >= 75 ? 'neon-red' : score >= 50 ? '' : 'neon-cyan'} style={{ fontSize: '0.8rem', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
          {score.toFixed(0)}
        </span>
      </div>
      <div style={{ height: 3, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
        <div style={{
          height: '100%',
          width: `${pct}%`,
          background: color,
          borderRadius: 2,
          boxShadow: `0 0 8px ${color}60`,
          transition: 'width 600ms ease',
        }} />
      </div>
    </div>
  )
}

function IntelRow({ label, value }) {
  return (
    <div style={{
      display: 'flex', justifyContent: 'space-between',
      padding: '3px 0', borderBottom: '1px solid rgba(255,255,255,0.03)',
    }}>
      <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>{label}</span>
      <span style={{ fontSize: '0.7rem', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{value || '—'}</span>
    </div>
  )
}

export default function IntelPanel() {
  const { events } = useThreatState()

  // Find the most recent event with IP data
  const latestWithIP = events.find(e => e.source_ip) || {}
  const intel = latestWithIP.threat_intel || {}
  const ip = latestWithIP.source_ip || '—'

  const threatScore = intel.threat_score ?? latestWithIP.risk_score ?? 0
  const abuseScore = intel.abuse_confidence_score ?? 0

  return (
    <Panel panelId={PANELS.INTEL} title="IP INTEL" icon="🔍" scanline>
      {ip === '—' ? (
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          height: '100%', color: 'var(--text-muted)', fontSize: '0.7rem',
          fontFamily: 'var(--font-display)',
        }}>
          NO IP DATA
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {/* IP header */}
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '0.85rem',
            fontWeight: 600,
            color: 'var(--cyan)',
            textShadow: '0 0 10px var(--cyan-glow)',
            marginBottom: 6,
          }}>
            {ip}
          </div>

          {/* Score gauges */}
          <ScoreGauge score={threatScore} label="Threat Score" />
          <ScoreGauge score={abuseScore} label="Abuse Confidence" />

          {/* Flags */}
          <div style={{ display: 'flex', gap: 6, marginTop: 4, marginBottom: 6, flexWrap: 'wrap' }}>
            {[
              { key: 'TOR', active: intel.is_tor || latestWithIP.ip_is_tor },
              { key: 'VPN', active: intel.is_vpn || latestWithIP.ip_is_vpn },
              { key: 'PROXY', active: intel.is_proxy || latestWithIP.ip_is_proxy },
              { key: 'DC', active: intel.is_datacenter || latestWithIP.ip_is_datacenter },
            ].map(f => (
              <span key={f.key} style={{
                fontSize: '0.55rem',
                padding: '2px 6px',
                borderRadius: 3,
                fontFamily: 'var(--font-display)',
                letterSpacing: '0.08em',
                background: f.active ? 'var(--red-dim)' : 'transparent',
                border: `1px solid ${f.active ? 'var(--border-danger)' : 'var(--border)'}`,
                color: f.active ? 'var(--red)' : 'var(--text-muted)',
              }}>
                {f.key}
              </span>
            ))}
          </div>

          {/* Data rows */}
          <IntelRow label="Country" value={
            intel.geo?.country_name || latestWithIP.source_country || '—'
          } />
          <IntelRow label="City" value={intel.geo?.city} />
          <IntelRow label="ASN" value={
            intel.geo?.asn || latestWithIP.source_asn
          } />
          <IntelRow label="ISP" value={intel.geo?.isp || latestWithIP.source_isp} />
          <IntelRow label="VT Malicious" value={intel.vt_malicious} />
          <IntelRow label="Reputation" value={
            (intel.reputation || '—').toUpperCase()
          } />
        </div>
      )}
    </Panel>
  )
}
