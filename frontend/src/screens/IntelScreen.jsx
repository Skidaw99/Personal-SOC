/**
 * Intel Screen — IP intelligence lookup tool.
 *
 * IP input, full enrichment display, recent lookups,
 * Export JSON / Copy Report buttons.
 */
import { useState, useCallback } from 'react'
import { api } from '../api'

function riskColor(s) {
  if (s >= 90) return 'var(--red)'
  if (s >= 70) return '#ff7c2a'
  if (s >= 50) return 'var(--amber)'
  return 'var(--cyan)'
}

function Flag({ label, active }) {
  return (
    <span className={`intel-badge ${active ? 'intel-badge-active' : 'intel-badge-inactive'}`}>
      {label}
    </span>
  )
}

function IntelSection({ title, children }) {
  return (
    <div className="intel-section">
      <h4 className="intel-section-title">{title}</h4>
      {children}
    </div>
  )
}

function IntelRow({ label, value, color }) {
  return (
    <div className="intel-row">
      <span className="form-label">{label}</span>
      <span className="intel-row-value" style={color ? { color } : {}}>{value ?? 'UNKNOWN'}</span>
    </div>
  )
}

export default function IntelScreen() {
  const [ip, setIp] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [history, setHistory] = useState([])

  const handleLookup = useCallback(async (lookupIp) => {
    const target = (lookupIp || ip).trim()
    if (!target) return

    setLoading(true)
    setError(null)

    try {
      const data = await api.lookupIP(target)
      setResult(data)
      setHistory(prev => {
        const filtered = prev.filter(h => h.ip !== target)
        return [{ ip: target, score: data.threat_score, timestamp: new Date().toISOString(), data }, ...filtered].slice(0, 10)
      })
    } catch (err) {
      setError(err.message)
      setResult(null)
    } finally {
      setLoading(false)
    }
  }, [ip])

  function exportJSON() {
    if (!result) return
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `intel-${result.ip}-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  function copyReport() {
    if (!result) return
    const report = [
      `IP Intelligence Report: ${result.ip}`,
      `Threat Score: ${result.threat_score} (${result.reputation})`,
      '',
      `Location: ${result.geo?.country_name || 'Unknown'}, ${result.geo?.city || 'Unknown'}`,
      `ASN: ${result.geo?.asn || 'Unknown'} | ISP: ${result.geo?.isp || 'Unknown'}`,
      '',
      `Flags: TOR=${result.flags?.is_tor} VPN=${result.flags?.is_vpn} PROXY=${result.flags?.is_proxy} DC=${result.flags?.is_datacenter}`,
      '',
      `AbuseIPDB: Confidence ${result.abuse?.confidence_score ?? 'N/A'}%, Reports: ${result.abuse?.total_reports ?? 'N/A'}`,
      `VirusTotal: Malicious ${result.virustotal?.malicious ?? 'N/A'}, Suspicious ${result.virustotal?.suspicious ?? 'N/A'}`,
      `Shodan: Ports [${(result.shodan?.open_ports || []).join(', ')}]`,
      `Vulns: [${(result.shodan?.vulnerabilities || []).join(', ')}]`,
      '',
      `Providers: ${(result.providers_used || []).join(', ')}`,
      `Cached: ${result.from_cache} | Duration: ${result.lookup_duration_ms}ms`,
    ].join('\n')
    navigator.clipboard.writeText(report)
  }

  return (
    <div className="screen">
      <h2 className="screen-title">IP INTELLIGENCE</h2>

      {/* Lookup input */}
      <form className="intel-lookup-form" onSubmit={e => { e.preventDefault(); handleLookup() }}>
        <input
          className="form-input intel-lookup-input"
          type="text"
          value={ip}
          onChange={e => setIp(e.target.value)}
          placeholder="Enter IP address..."
          disabled={loading}
        />
        <button className="btn btn-cyan" type="submit" disabled={loading || !ip.trim()}>
          {loading ? 'SCANNING...' : 'LOOKUP'}
        </button>
      </form>

      {error && <div className="error-card" style={{ marginTop: 12 }}><span className="error-text">{error}</span></div>}

      <div className="intel-content">
        {/* Result display */}
        {result && (
          <div className="intel-result">
            {/* Header */}
            <div className="intel-result-header">
              <div>
                <div className="intel-ip-large">{result.ip}</div>
                <div className="intel-reputation" style={{ color: riskColor(result.threat_score) }}>
                  {result.reputation?.toUpperCase() || 'UNKNOWN'}
                </div>
              </div>
              <div className="intel-score-large" style={{ color: riskColor(result.threat_score) }}>
                {(result.threat_score || 0).toFixed(0)}
              </div>
            </div>

            {/* Score bar */}
            <div className="intel-score-bar" style={{ marginBottom: 16 }}>
              <div className="intel-score-fill" style={{
                width: `${Math.min(100, result.threat_score || 0)}%`,
                background: `linear-gradient(90deg, ${riskColor(result.threat_score)}cc, ${riskColor(result.threat_score)})`,
                boxShadow: `0 0 8px ${riskColor(result.threat_score)}40`,
              }} />
            </div>

            {/* Location */}
            <IntelSection title="LOCATION">
              <IntelRow label="Country" value={result.geo?.country_name} />
              <IntelRow label="City" value={result.geo?.city} />
              <IntelRow label="ASN" value={result.geo?.asn ? `AS${result.geo.asn}` : null} />
              <IntelRow label="ISP" value={result.geo?.isp} />
              {result.geo?.latitude && (
                <IntelRow label="Coordinates" value={`${result.geo.latitude.toFixed(4)}, ${result.geo.longitude?.toFixed(4)}`} />
              )}
            </IntelSection>

            {/* Threat flags */}
            <IntelSection title="THREAT FLAGS">
              <div className="intel-badges" style={{ marginTop: 4 }}>
                <Flag label="TOR" active={result.flags?.is_tor} />
                <Flag label="VPN" active={result.flags?.is_vpn} />
                <Flag label="PROXY" active={result.flags?.is_proxy} />
                <Flag label="DATACENTER" active={result.flags?.is_datacenter} />
              </div>
            </IntelSection>

            {/* AbuseIPDB */}
            <IntelSection title="ABUSEIPDB">
              <IntelRow label="Confidence" value={result.abuse?.confidence_score != null ? `${result.abuse.confidence_score}%` : null}
                color={result.abuse?.confidence_score >= 70 ? 'var(--red)' : undefined} />
              <IntelRow label="Total Reports" value={result.abuse?.total_reports} />
            </IntelSection>

            {/* VirusTotal */}
            <IntelSection title="VIRUSTOTAL">
              <IntelRow label="Malicious" value={result.virustotal?.malicious}
                color={result.virustotal?.malicious > 0 ? 'var(--red)' : 'var(--green)'} />
              <IntelRow label="Suspicious" value={result.virustotal?.suspicious}
                color={result.virustotal?.suspicious > 0 ? 'var(--amber)' : undefined} />
              <IntelRow label="Community Score" value={result.virustotal?.community_score} />
            </IntelSection>

            {/* Shodan */}
            <IntelSection title="SHODAN">
              <IntelRow label="Open Ports" value={
                (result.shodan?.open_ports || []).length > 0
                  ? result.shodan.open_ports.join(', ')
                  : 'None detected'
              } />
              {(result.shodan?.vulnerabilities || []).length > 0 && (
                <IntelRow label="Vulnerabilities" value={result.shodan.vulnerabilities.join(', ')} color="var(--red)" />
              )}
              {(result.shodan?.hostnames || []).length > 0 && (
                <IntelRow label="Hostnames" value={result.shodan.hostnames.join(', ')} />
              )}
            </IntelSection>

            {/* Metadata */}
            <IntelSection title="METADATA">
              <IntelRow label="Providers" value={(result.providers_used || []).join(', ')} />
              {Object.keys(result.providers_failed || {}).length > 0 && (
                <IntelRow label="Failed" value={Object.keys(result.providers_failed).join(', ')} color="var(--red)" />
              )}
              <IntelRow label="Cached" value={result.from_cache ? 'Yes' : 'No'} />
              <IntelRow label="Duration" value={result.lookup_duration_ms ? `${result.lookup_duration_ms.toFixed(0)}ms` : null} />
            </IntelSection>

            {/* Action buttons */}
            <div className="intel-actions">
              <button className="btn btn-cyan" onClick={exportJSON}>EXPORT JSON</button>
              <button className="btn btn-muted" onClick={copyReport}>COPY REPORT</button>
            </div>
          </div>
        )}

        {/* Recent lookups */}
        {history.length > 0 && (
          <div className="intel-history">
            <h3 className="section-title">RECENT LOOKUPS</h3>
            {history.map(h => (
              <div
                key={h.ip + h.timestamp}
                className="intel-history-card"
                onClick={() => { setIp(h.ip); setResult(h.data) }}
              >
                <span className="intel-history-ip">{h.ip}</span>
                <span className="intel-history-score" style={{ color: riskColor(h.score) }}>
                  {(h.score || 0).toFixed(0)}
                </span>
                <span className="intel-history-time">
                  {new Date(h.timestamp).toLocaleTimeString('en-GB', { hour12: false })}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
