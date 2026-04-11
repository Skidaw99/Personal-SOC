/**
 * Dashboard Screen — operational overview.
 *
 * Platform status rows, 6 stat cards, alert distribution,
 * clickable recent alerts. Auto-refresh 30s.
 */
import { useState, useEffect, useRef } from 'react'
import { api } from '../api'
import { useGlobalThreat } from '../hooks/useThreatState'

const PLATFORM_ICONS = {
  facebook: '📘', instagram: '📷', twitter: '🐦',
  linkedin: '💼', tiktok: '🎵', youtube: '▶️',
}

const CATEGORY_COLORS = {
  unauthorized_login: 'var(--amber)',
  account_takeover: 'var(--red)',
  api_token_misuse: '#ff7c2a',
  suspicious_activity: 'var(--cyan)',
}

function riskColor(s) {
  if (s >= 90) return 'var(--red)'
  if (s >= 70) return '#ff7c2a'
  if (s >= 50) return 'var(--amber)'
  return 'var(--cyan)'
}

export default function DashboardScreen({ onNavigate }) {
  const { threatLevel, threatColor } = useGlobalThreat()
  const [dashboard, setDashboard] = useState(null)
  const [accounts, setAccounts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const timerRef = useRef(null)

  async function fetchData() {
    try {
      const [dash, accts] = await Promise.all([
        api.getDashboard(),
        api.getAccounts(),
      ])
      setDashboard(dash)
      setAccounts(accts || [])
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
    timerRef.current = setInterval(fetchData, 30000)
    return () => clearInterval(timerRef.current)
  }, [])

  if (loading) {
    return (
      <div className="screen screen-center">
        <span className="loading-text">LOADING DASHBOARD...</span>
      </div>
    )
  }

  if (error) {
    return (
      <div className="screen screen-center">
        <div className="error-card">
          <span className="error-text">{error}</span>
          <button className="btn btn-cyan" onClick={fetchData}>RETRY</button>
        </div>
      </div>
    )
  }

  const s = dashboard?.summary || {}
  const alertByCat = dashboard?.alert_by_category || {}
  const eventBySev = dashboard?.event_by_severity || {}
  const platformDist = dashboard?.platform_distribution || {}
  const recentAlerts = dashboard?.recent_open_alerts || []
  const totalAlerts = Object.values(alertByCat).reduce((a, b) => a + b, 0) || 1

  // Build platform rows from accounts + distribution
  const platformGroups = {}
  for (const acc of accounts) {
    if (!platformGroups[acc.platform]) {
      platformGroups[acc.platform] = { count: 0, lastChecked: null }
    }
    platformGroups[acc.platform].count++
    if (acc.last_checked_at && (!platformGroups[acc.platform].lastChecked || acc.last_checked_at > platformGroups[acc.platform].lastChecked)) {
      platformGroups[acc.platform].lastChecked = acc.last_checked_at
    }
  }

  return (
    <div className="screen">
      {/* Threat level header */}
      <div className="dashboard-header">
        <h2 className="screen-title">OPERATIONAL DASHBOARD</h2>
        <div className="nav-threat-indicator" style={{ fontSize: 14 }}>
          <span className="nav-threat-dot" style={{
            background: threatColor, boxShadow: `0 0 8px ${threatColor}`,
            width: 8, height: 8,
          }} />
          <span style={{ color: threatColor, fontWeight: 700 }}>THREATCON: {threatLevel}</span>
        </div>
      </div>

      {/* Platform status rows */}
      {Object.keys(platformGroups).length > 0 && (
        <div className="dashboard-section">
          <h3 className="section-title">PLATFORM STATUS</h3>
          {Object.entries(platformGroups).map(([platform, data]) => {
            const alertCount = platformDist[platform] || 0
            const status = alertCount >= 5 ? 'CRITICAL' : alertCount >= 1 ? 'WARNING' : 'OK'
            const statusColor = status === 'CRITICAL' ? 'var(--red)' : status === 'WARNING' ? 'var(--amber)' : 'var(--green)'
            return (
              <div key={platform} className="platform-row">
                <span className="platform-icon">{PLATFORM_ICONS[platform] || '🔗'}</span>
                <span className="platform-name">{platform.toUpperCase()}</span>
                <span className="platform-stat">{data.count} accounts</span>
                <span className="platform-stat">
                  {data.lastChecked ? new Date(data.lastChecked).toLocaleTimeString('en-GB', { hour12: false }) : 'never'}
                </span>
                {alertCount > 0 && (
                  <span className="platform-alert-badge">{alertCount} alerts</span>
                )}
                <span className="platform-status" style={{ color: statusColor }}>{status}</span>
              </div>
            )
          })}
        </div>
      )}

      {/* Stat cards */}
      <div className="dashboard-section">
        <h3 className="section-title">OVERVIEW</h3>
        <div className="stat-grid">
          <div className="stat-card">
            <div className="stat-value">{s.total_accounts || 0}</div>
            <div className="stat-label">TOTAL ACCOUNTS</div>
          </div>
          <div className="stat-card">
            <div className="stat-value" style={{ color: s.open_alerts > 0 ? 'var(--amber)' : 'var(--green)' }}>
              {s.open_alerts || 0}
            </div>
            <div className="stat-label">OPEN ALERTS</div>
          </div>
          <div className="stat-card">
            <div className="stat-value" style={{ color: 'var(--red)' }}>
              {recentAlerts.filter(a => a.risk_score >= 90).length}
            </div>
            <div className="stat-label">CRITICAL ALERTS</div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{s.total_events || 0}</div>
            <div className="stat-label">EVENTS 24H</div>
          </div>
          <div className="stat-card">
            <div className="stat-value" style={{ color: riskColor(s.avg_open_risk_score || 0) }}>
              {(s.avg_open_risk_score || 0).toFixed(1)}
            </div>
            <div className="stat-label">AVG RISK SCORE</div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{(s.acknowledged_alerts || 0) + (s.resolved_alerts || 0)}</div>
            <div className="stat-label">HANDLED ALERTS</div>
          </div>
        </div>
      </div>

      {/* Alert distribution */}
      <div className="dashboard-section">
        <h3 className="section-title">ALERT DISTRIBUTION</h3>
        <div className="distribution-bars">
          {Object.entries(alertByCat).map(([cat, count]) => {
            const pct = Math.round((count / totalAlerts) * 100)
            const color = CATEGORY_COLORS[cat] || 'var(--cyan)'
            return (
              <div key={cat} className="distribution-row">
                <span className="distribution-label">{cat.replace(/_/g, ' ').toUpperCase()}</span>
                <div className="distribution-bar-track">
                  <div className="distribution-bar-fill" style={{ width: `${pct}%`, background: color }} />
                </div>
                <span className="distribution-count" style={{ color }}>{count}</span>
              </div>
            )
          })}
        </div>
      </div>

      {/* Recent alerts */}
      <div className="dashboard-section">
        <h3 className="section-title">RECENT OPEN ALERTS</h3>
        {recentAlerts.length === 0 ? (
          <div className="empty-state">NO OPEN ALERTS</div>
        ) : (
          <div className="recent-alerts">
            {recentAlerts.slice(0, 10).map(alert => (
              <div
                key={alert.id}
                className="recent-alert-card"
                onClick={() => onNavigate?.('alerts')}
                style={{ cursor: 'pointer' }}
              >
                <span className="recent-alert-risk" style={{ color: riskColor(alert.risk_score) }}>
                  {alert.risk_score?.toFixed(0) || '0'}
                </span>
                <div className="recent-alert-info">
                  <span className="recent-alert-title">{alert.title || 'Untitled'}</span>
                  <span className="recent-alert-meta">
                    {(alert.category || '').replace(/_/g, ' ')} · {alert.created_at ? new Date(alert.created_at).toLocaleTimeString('en-GB', { hour12: false }) : ''}
                  </span>
                </div>
                <span className="recent-alert-arrow">&#8250;</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
