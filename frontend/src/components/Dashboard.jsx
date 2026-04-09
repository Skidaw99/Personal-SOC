import { useState, useEffect, useCallback } from 'react'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts'
import { api } from '../api'

// ─── Constants ──────────────────────────────────────────────────────────────

const SEVERITY_COLOR = { critical: '#ff3b3b', high: '#ff7c2a', medium: '#f5c842', low: '#3b82f6', info: '#3d5a7a' }
const CATEGORY_LABEL = { unauthorized_login: 'Unauth. Login', account_takeover: 'Takeover', api_token_misuse: 'Token Misuse', suspicious_activity: 'Suspicious' }
const PLATFORM_ICON  = { facebook: '📘', instagram: '📸', twitter: '🐦', linkedin: '💼', tiktok: '🎵', youtube: '📺' }
const STATUS_COLOR   = { open: '#ff3b3b', acknowledged: '#f5c842', resolved: '#22c55e', false_positive: '#3d5a7a' }

const PLATFORMS = ['facebook','instagram','twitter','linkedin','tiktok','youtube']

function riskColor(score) {
  if (score >= 80) return '#ff3b3b'
  if (score >= 60) return '#ff7c2a'
  if (score >= 40) return '#f5c842'
  return '#3b82f6'
}

// ─── Reusable UI primitives ──────────────────────────────────────────────────

function Card({ children, style = {} }) {
  return (
    <div style={{
      background: 'var(--bg-card)', border: '1px solid var(--border)',
      borderRadius: 12, padding: 24, ...style,
    }}>
      {children}
    </div>
  )
}

function Badge({ label, color }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: '3px 10px', borderRadius: 20,
      background: `${color}18`, border: `1px solid ${color}40`,
      color, fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5,
    }}>
      <span style={{ width: 5, height: 5, borderRadius: '50%', background: color, display: 'inline-block' }} />
      {label}
    </span>
  )
}

function StatCard({ label, value, sub, accent, pulse }) {
  return (
    <Card style={{ position: 'relative', overflow: 'hidden' }}>
      {pulse && (
        <span style={{
          position: 'absolute', top: 16, right: 16,
          width: 8, height: 8, borderRadius: '50%', background: accent,
          boxShadow: `0 0 0 3px ${accent}30`,
          animation: 'pulse 2s infinite',
        }} />
      )}
      <div style={{ fontSize: 11, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>
        {label}
      </div>
      <div style={{ fontSize: 36, fontWeight: 800, fontFamily: 'var(--font-display)', color: accent || 'var(--text-primary)', lineHeight: 1 }}>
        {value}
      </div>
      {sub && <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>{sub}</div>}
    </Card>
  )
}

function SectionTitle({ children }) {
  return (
    <h2 style={{
      fontFamily: 'var(--font-display)', fontWeight: 700, fontSize: 13,
      color: 'var(--text-secondary)', textTransform: 'uppercase',
      letterSpacing: 2, marginBottom: 16,
    }}>
      {children}
    </h2>
  )
}

// ─── Alerts Table ────────────────────────────────────────────────────────────

function AlertsTable({ alerts, onUpdate }) {
  const [updating, setUpdating] = useState(null)

  async function handleStatus(id, status) {
    setUpdating(id)
    try {
      await api.updateAlert(id, { status })
      onUpdate()
    } catch(e) {
      alert(e.message)
    } finally {
      setUpdating(null)
    }
  }

  if (!alerts.length) return (
    <div style={{ textAlign: 'center', padding: '48px 0', color: 'var(--text-muted)', fontSize: 13 }}>
      ✓ No alerts found
    </div>
  )

  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
        <thead>
          <tr>
            {['Risk','Platform','Account','Category','Status','Title','Dispatched','Actions'].map(h => (
              <th key={h} style={{
                textAlign: 'left', padding: '8px 12px',
                borderBottom: '1px solid var(--border)',
                color: 'var(--text-muted)', fontWeight: 500, fontSize: 11,
                textTransform: 'uppercase', letterSpacing: 0.8, whiteSpace: 'nowrap',
              }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {alerts.map(a => (
            <tr key={a.id} style={{
              borderBottom: '1px solid var(--border)',
              transition: 'background 0.1s',
            }}
              onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-elevated)'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
            >
              {/* Risk score */}
              <td style={{ padding: '12px 12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{
                    width: 36, height: 36, borderRadius: 8, display: 'flex',
                    alignItems: 'center', justifyContent: 'center',
                    background: `${riskColor(a.risk_score)}18`,
                    border: `1px solid ${riskColor(a.risk_score)}40`,
                    color: riskColor(a.risk_score), fontWeight: 700, fontSize: 13,
                  }}>
                    {a.risk_score.toFixed(0)}
                  </div>
                </div>
              </td>
              {/* Platform */}
              <td style={{ padding: '12px 12px', whiteSpace: 'nowrap' }}>
                <span style={{ fontSize: 14 }}>{PLATFORM_ICON[a.platform] || '🌐'}</span>
                <span style={{ color: 'var(--text-secondary)', marginLeft: 6 }}>{a.platform}</span>
              </td>
              {/* Account */}
              <td style={{ padding: '12px 12px', color: 'var(--accent-cyan)', whiteSpace: 'nowrap' }}>@{a.username}</td>
              {/* Category */}
              <td style={{ padding: '12px 12px' }}>
                <Badge label={CATEGORY_LABEL[a.category] || a.category} color={riskColor(a.risk_score)} />
              </td>
              {/* Status */}
              <td style={{ padding: '12px 12px' }}>
                <Badge label={a.status} color={STATUS_COLOR[a.status] || '#3b82f6'} />
              </td>
              {/* Title */}
              <td style={{ padding: '12px 12px', color: 'var(--text-primary)', maxWidth: 260 }}>
                <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                  title={a.title}>{a.title}</div>
                <div style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 2 }}>
                  {new Date(a.created_at).toLocaleString()}
                </div>
              </td>
              {/* Dispatched */}
              <td style={{ padding: '12px 12px' }}>
                <div style={{ display: 'flex', gap: 6 }}>
                  <span title="Email" style={{ fontSize: 14 }}>{a.email_sent ? '✉️' : '⬜'}</span>
                  <span title="Webhook" style={{ fontSize: 14 }}>{a.webhook_sent ? '🔗' : '⬜'}</span>
                </div>
              </td>
              {/* Actions */}
              <td style={{ padding: '12px 12px' }}>
                {a.status === 'open' && (
                  <div style={{ display: 'flex', gap: 6 }}>
                    <ActionBtn
                      label="ACK" color="#f5c842"
                      disabled={updating === a.id}
                      onClick={() => handleStatus(a.id, 'acknowledged')}
                    />
                    <ActionBtn
                      label="RESOLVE" color="#22c55e"
                      disabled={updating === a.id}
                      onClick={() => handleStatus(a.id, 'resolved')}
                    />
                    <ActionBtn
                      label="FP" color="#3d5a7a"
                      disabled={updating === a.id}
                      onClick={() => handleStatus(a.id, 'false_positive')}
                    />
                  </div>
                )}
                {a.status !== 'open' && (
                  <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ActionBtn({ label, color, onClick, disabled }) {
  return (
    <button onClick={onClick} disabled={disabled} style={{
      padding: '4px 8px', background: `${color}15`,
      border: `1px solid ${color}40`, borderRadius: 6,
      color, fontSize: 10, fontWeight: 700, letterSpacing: 0.5,
      fontFamily: 'var(--font-mono)',
      opacity: disabled ? 0.5 : 1,
      transition: 'all 0.1s',
    }}>{label}</button>
  )
}

// ─── Add Account Modal ────────────────────────────────────────────────────────

function AddAccountModal({ onClose, onAdded }) {
  const [form, setForm] = useState({ platform: 'facebook', platform_user_id: '', username: '', display_name: '', access_token: '' })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit(e) {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      await api.addAccount(form)
      onAdded()
      onClose()
    } catch(e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      zIndex: 1000, padding: 24,
    }}>
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border-bright)',
        borderRadius: 16, padding: 32, width: '100%', maxWidth: 480,
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
          <h3 style={{ fontFamily: 'var(--font-display)', fontWeight: 700, fontSize: 18 }}>Add Social Account</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: 20 }}>×</button>
        </div>

        <form onSubmit={handleSubmit}>
          <Field label="Platform">
            <select value={form.platform} onChange={e => setForm({...form, platform: e.target.value})} style={fieldStyle}>
              {PLATFORMS.map(p => <option key={p} value={p}>{PLATFORM_ICON[p]} {p.charAt(0).toUpperCase()+p.slice(1)}</option>)}
            </select>
          </Field>
          <Field label="Platform User ID">
            <input required value={form.platform_user_id} onChange={e => setForm({...form, platform_user_id: e.target.value})} style={fieldStyle} placeholder="e.g. 123456789" />
          </Field>
          <Field label="Username">
            <input required value={form.username} onChange={e => setForm({...form, username: e.target.value})} style={fieldStyle} placeholder="e.g. yourhandle" />
          </Field>
          <Field label="Display Name">
            <input value={form.display_name} onChange={e => setForm({...form, display_name: e.target.value})} style={fieldStyle} placeholder="Optional" />
          </Field>
          <Field label="Access Token">
            <input required type="password" value={form.access_token} onChange={e => setForm({...form, access_token: e.target.value})} style={fieldStyle} placeholder="OAuth access token (encrypted at rest)" />
          </Field>
          {error && <div style={{ color: '#ff7070', fontSize: 13, marginBottom: 16 }}>{error}</div>}
          <div style={{ display: 'flex', gap: 12, marginTop: 8 }}>
            <button type="button" onClick={onClose} style={{ flex: 1, padding: '11px', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>Cancel</button>
            <button type="submit" disabled={loading} style={{ flex: 1, padding: '11px', background: 'var(--accent-blue)', border: 'none', borderRadius: 8, color: '#fff', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
              {loading ? 'Adding…' : 'Add Account'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function Field({ label, children }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <label style={{ display: 'block', fontSize: 11, color: 'var(--text-secondary)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 1 }}>{label}</label>
      {children}
    </div>
  )
}

const fieldStyle = {
  width: '100%', padding: '10px 14px',
  background: 'var(--bg-elevated)', border: '1px solid var(--border-bright)',
  borderRadius: 8, color: 'var(--text-primary)',
  fontFamily: 'var(--font-mono)', fontSize: 13, outline: 'none',
}

// ─── Alert Detail Modal ───────────────────────────────────────────────────────

function AlertDetailModal({ alert, onClose, onUpdate }) {
  if (!alert) return null

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.8)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      zIndex: 1000, padding: 24,
    }}>
      <div style={{
        background: 'var(--bg-card)', border: `1px solid ${riskColor(alert.risk_score)}50`,
        borderRadius: 16, padding: 32, width: '100%', maxWidth: 560, maxHeight: '85vh', overflowY: 'auto',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
          <div>
            <Badge label={CATEGORY_LABEL[alert.category] || alert.category} color={riskColor(alert.risk_score)} />
            <h3 style={{ fontFamily: 'var(--font-display)', fontWeight: 700, fontSize: 17, marginTop: 10, lineHeight: 1.4 }}>{alert.title}</h3>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: 22, marginLeft: 16, flexShrink: 0 }}>×</button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 20 }}>
          <InfoBlock label="Platform" value={`${PLATFORM_ICON[alert.platform]} ${alert.platform}`} />
          <InfoBlock label="Account" value={`@${alert.username}`} accent="var(--accent-cyan)" />
          <InfoBlock label="Risk Score" value={`${alert.risk_score.toFixed(0)}/100`} accent={riskColor(alert.risk_score)} />
          <InfoBlock label="Status" value={alert.status.toUpperCase()} accent={STATUS_COLOR[alert.status]} />
        </div>

        <DetailSection title="Detection Details" text={alert.description} />
        <DetailSection title="Recommended Action" text={alert.recommended_action} />

        {alert.evidence && Object.keys(alert.evidence).length > 0 && (
          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>Evidence</div>
            <div style={{ background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 8, padding: '12px 16px' }}>
              {Object.entries(alert.evidence).map(([k, v]) => (
                <div key={k} style={{ display: 'flex', gap: 12, marginBottom: 6, fontSize: 12 }}>
                  <span style={{ color: 'var(--text-muted)', minWidth: 160 }}>{k}</span>
                  <span style={{ color: 'var(--accent-cyan)', wordBreak: 'break-all' }}>{JSON.stringify(v)}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, marginTop: 4, fontSize: 12, color: 'var(--text-muted)' }}>
          <span>Email: {alert.email_sent ? '✅ sent' : '❌ not sent'}</span>
          <span style={{ margin: '0 4px' }}>·</span>
          <span>Webhook: {alert.webhook_sent ? '✅ sent' : '❌ not sent'}</span>
        </div>
      </div>
    </div>
  )
}

function InfoBlock({ label, value, accent }) {
  return (
    <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, padding: '10px 14px' }}>
      <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 14, fontWeight: 600, color: accent || 'var(--text-primary)' }}>{value}</div>
    </div>
  )
}

function DetailSection({ title, text }) {
  if (!text) return null
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{ fontSize: 11, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>{title}</div>
      <p style={{ fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.7, whiteSpace: 'pre-line' }}>{text}</p>
    </div>
  )
}

// ─── Main Dashboard ───────────────────────────────────────────────────────────

export default function Dashboard({ onLogout }) {
  const [view, setView] = useState('overview') // overview | alerts | accounts
  const [summary, setSummary] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [accounts, setAccounts] = useState([])
  const [alertFilter, setAlertFilter] = useState('open')
  const [loading, setLoading] = useState(true)
  const [showAddAccount, setShowAddAccount] = useState(false)
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [lastRefresh, setLastRefresh] = useState(new Date())

  const loadSummary = useCallback(async () => {
    try {
      const data = await api.getSummary()
      setSummary(data)
    } catch (e) { console.error(e) }
  }, [])

  const loadAlerts = useCallback(async () => {
    try {
      const data = await api.getAlerts(alertFilter ? { status: alertFilter } : {})
      setAlerts(data)
    } catch (e) { console.error(e) }
  }, [alertFilter])

  const loadAccounts = useCallback(async () => {
    try {
      const data = await api.getAccounts()
      setAccounts(data)
    } catch (e) { console.error(e) }
  }, [])

  const loadAll = useCallback(async () => {
    setLoading(true)
    await Promise.all([loadSummary(), loadAlerts(), loadAccounts()])
    setLastRefresh(new Date())
    setLoading(false)
  }, [loadSummary, loadAlerts, loadAccounts])

  useEffect(() => { loadAll() }, [loadAll])
  useEffect(() => { loadAlerts() }, [loadAlerts])

  // Auto-refresh every 60s
  useEffect(() => {
    const t = setInterval(loadAll, 60000)
    return () => clearInterval(t)
  }, [loadAll])

  async function handleDeleteAccount(id) {
    if (!confirm('Remove this account from monitoring?')) return
    try {
      await api.deleteAccount(id)
      loadAccounts()
    } catch(e) { alert(e.message) }
  }

  const navItems = [
    { id: 'overview', label: '◈ Overview' },
    { id: 'alerts',   label: '⚠ Alerts' },
    { id: 'accounts', label: '◉ Accounts' },
  ]

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>

      {/* ── Top nav ── */}
      <header style={{
        background: 'var(--bg-surface)', borderBottom: '1px solid var(--border)',
        padding: '0 32px', display: 'flex', alignItems: 'center', gap: 0,
        position: 'sticky', top: 0, zIndex: 100, height: 56,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginRight: 40 }}>
          <span style={{ fontSize: 20 }}>🛡</span>
          <span style={{ fontFamily: 'var(--font-display)', fontWeight: 800, fontSize: 15, color: 'var(--text-primary)', letterSpacing: '-0.3px' }}>
            SFD
          </span>
          {summary?.critical_alerts > 0 && (
            <span style={{
              background: '#ff3b3b', color: '#fff', borderRadius: 20,
              padding: '1px 7px', fontSize: 11, fontWeight: 700,
            }}>{summary.critical_alerts}</span>
          )}
        </div>

        <nav style={{ display: 'flex', gap: 4, flex: 1 }}>
          {navItems.map(n => (
            <button key={n.id} onClick={() => setView(n.id)} style={{
              padding: '8px 16px', background: view === n.id ? 'var(--bg-card)' : 'transparent',
              border: view === n.id ? '1px solid var(--border)' : '1px solid transparent',
              borderRadius: 8, color: view === n.id ? 'var(--text-primary)' : 'var(--text-muted)',
              fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 500,
              transition: 'all 0.15s',
            }}>{n.label}</button>
          ))}
        </nav>

        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>
            ↻ {lastRefresh.toLocaleTimeString()}
          </span>
          <button onClick={loadAll} style={{
            padding: '6px 12px', background: 'var(--bg-card)',
            border: '1px solid var(--border)', borderRadius: 6,
            color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: 11,
          }}>Refresh</button>
          <button onClick={onLogout} style={{
            padding: '6px 12px', background: 'transparent',
            border: '1px solid var(--border)', borderRadius: 6,
            color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 11,
          }}>Sign out</button>
        </div>
      </header>

      {/* ── Content ── */}
      <main style={{ flex: 1, padding: '32px', maxWidth: 1400, margin: '0 auto', width: '100%' }}>

        {loading && !summary && (
          <div style={{ textAlign: 'center', padding: '80px 0', color: 'var(--text-muted)', fontSize: 13 }}>
            Loading dashboard…
          </div>
        )}

        {/* ── OVERVIEW ── */}
        {view === 'overview' && summary && (
          <div>
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontFamily: 'var(--font-display)', fontWeight: 800, fontSize: 26, letterSpacing: '-0.5px' }}>
                Security Overview
              </h1>
              <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginTop: 4 }}>
                Real-time fraud detection across all monitored social accounts
              </p>
            </div>

            {/* Stat cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 16, marginBottom: 32 }}>
              <StatCard label="Accounts Monitored"  value={summary.total_accounts}  sub="across all platforms" accent="var(--accent-cyan)" />
              <StatCard label="Open Alerts"         value={summary.open_alerts}     sub="require attention"    accent={summary.open_alerts > 0 ? 'var(--accent-orange)' : 'var(--accent-green)'} pulse={summary.open_alerts > 0} />
              <StatCard label="Critical Alerts"     value={summary.critical_alerts} sub="risk score ≥ 80"      accent={summary.critical_alerts > 0 ? 'var(--accent-red)' : 'var(--text-secondary)'} pulse={summary.critical_alerts > 0} />
              <StatCard label="Alerts (24h)"        value={summary.alerts_24h}      sub="last 24 hours"        accent="var(--accent-yellow)" />
              <StatCard label="Events (24h)"        value={summary.events_24h}      sub="security events"      accent="var(--text-secondary)" />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1.8fr 1fr', gap: 20, marginBottom: 20 }}>
              {/* Alert trend */}
              <Card>
                <SectionTitle>Alert Volume — Last 7 Days</SectionTitle>
                {summary.daily_volume?.length > 0 ? (
                  <ResponsiveContainer width="100%" height={180}>
                    <AreaChart data={summary.daily_volume} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                      <defs>
                        <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ff3b3b" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="#ff3b3b" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="date" tick={{ fill: '#3d5a7a', fontSize: 10, fontFamily: 'var(--font-mono)' }} tickLine={false} axisLine={false} />
                      <YAxis tick={{ fill: '#3d5a7a', fontSize: 10, fontFamily: 'var(--font-mono)' }} tickLine={false} axisLine={false} allowDecimals={false} />
                      <Tooltip
                        contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, fontFamily: 'var(--font-mono)', fontSize: 12 }}
                        labelStyle={{ color: 'var(--text-secondary)' }}
                        itemStyle={{ color: '#ff3b3b' }}
                      />
                      <Area type="monotone" dataKey="count" stroke="#ff3b3b" strokeWidth={2} fill="url(#alertGrad)" dot={false} />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div style={{ height: 180, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                    No alert data yet
                  </div>
                )}
              </Card>

              {/* By platform */}
              <Card>
                <SectionTitle>Alerts by Platform</SectionTitle>
                {Object.keys(summary.alerts_by_platform || {}).length > 0 ? (
                  <ResponsiveContainer width="100%" height={180}>
                    <BarChart data={Object.entries(summary.alerts_by_platform).map(([k,v]) => ({ platform: k, count: v }))} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                      <XAxis dataKey="platform" tick={{ fill: '#3d5a7a', fontSize: 10, fontFamily: 'var(--font-mono)' }} tickLine={false} axisLine={false} />
                      <YAxis tick={{ fill: '#3d5a7a', fontSize: 10, fontFamily: 'var(--font-mono)' }} tickLine={false} axisLine={false} allowDecimals={false} />
                      <Tooltip contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, fontFamily: 'var(--font-mono)', fontSize: 12 }} />
                      <Bar dataKey="count" radius={[4,4,0,0]}>
                        {Object.keys(summary.alerts_by_platform).map((_, i) => (
                          <Cell key={i} fill={['#3b82f6','#a855f7','#06b6d4','#0077b5','#ff0050','#ff0000'][i % 6]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div style={{ height: 180, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                    No platform data yet
                  </div>
                )}
              </Card>
            </div>

            {/* Recent alerts */}
            <Card>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <SectionTitle>Recent Alerts</SectionTitle>
                <button onClick={() => setView('alerts')} style={{
                  background: 'none', border: '1px solid var(--border)', borderRadius: 6,
                  color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: 11, padding: '4px 12px',
                }}>View all →</button>
              </div>
              {summary.recent_alerts?.length > 0 ? (
                <div>
                  {summary.recent_alerts.map(a => (
                    <div key={a.id}
                      onClick={() => setSelectedAlert(a)}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 14,
                        padding: '10px 0', borderBottom: '1px solid var(--border)',
                        cursor: 'pointer', transition: 'opacity 0.1s',
                      }}
                      onMouseEnter={e => e.currentTarget.style.opacity = '0.75'}
                      onMouseLeave={e => e.currentTarget.style.opacity = '1'}
                    >
                      <div style={{
                        width: 34, height: 34, borderRadius: 8, display: 'flex',
                        alignItems: 'center', justifyContent: 'center',
                        background: `${riskColor(a.risk_score)}18`,
                        border: `1px solid ${riskColor(a.risk_score)}40`,
                        color: riskColor(a.risk_score), fontWeight: 700, fontSize: 12, flexShrink: 0,
                      }}>{a.risk_score.toFixed(0)}</div>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 13, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.title}</div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                          {PLATFORM_ICON[a.platform]} {a.platform} · @{a.username} · {new Date(a.created_at).toLocaleString()}
                        </div>
                      </div>
                      <Badge label={a.status} color={STATUS_COLOR[a.status] || '#3b82f6'} />
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ textAlign: 'center', padding: '32px 0', color: 'var(--text-muted)', fontSize: 13 }}>
                  ✓ No recent alerts
                </div>
              )}
            </Card>
          </div>
        )}

        {/* ── ALERTS VIEW ── */}
        {view === 'alerts' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
              <div>
                <h1 style={{ fontFamily: 'var(--font-display)', fontWeight: 800, fontSize: 26, letterSpacing: '-0.5px' }}>Fraud Alerts</h1>
                <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginTop: 4 }}>All detected security events</p>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                {['open','acknowledged','resolved','false_positive',''].map(s => (
                  <button key={s} onClick={() => setAlertFilter(s)} style={{
                    padding: '7px 14px',
                    background: alertFilter === s ? 'var(--bg-elevated)' : 'transparent',
                    border: alertFilter === s ? '1px solid var(--border-bright)' : '1px solid var(--border)',
                    borderRadius: 7, color: alertFilter === s ? 'var(--text-primary)' : 'var(--text-muted)',
                    fontFamily: 'var(--font-mono)', fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5,
                  }}>{s || 'All'}</button>
                ))}
              </div>
            </div>
            <Card style={{ padding: '8px 0' }}>
              <AlertsTable
                alerts={alerts}
                onUpdate={() => { loadAlerts(); loadSummary() }}
              />
            </Card>
          </div>
        )}

        {/* ── ACCOUNTS VIEW ── */}
        {view === 'accounts' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
              <div>
                <h1 style={{ fontFamily: 'var(--font-display)', fontWeight: 800, fontSize: 26, letterSpacing: '-0.5px' }}>Monitored Accounts</h1>
                <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginTop: 4 }}>{accounts.length} account{accounts.length !== 1 ? 's' : ''} registered</p>
              </div>
              <button onClick={() => setShowAddAccount(true)} style={{
                padding: '10px 20px', background: 'var(--accent-blue)', border: 'none',
                borderRadius: 8, color: '#fff', fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 600,
              }}>+ Add Account</button>
            </div>

            {accounts.length === 0 ? (
              <Card style={{ textAlign: 'center', padding: '64px 32px' }}>
                <div style={{ fontSize: 40, marginBottom: 16 }}>🛡</div>
                <h3 style={{ fontFamily: 'var(--font-display)', fontWeight: 700, fontSize: 18, marginBottom: 8 }}>No accounts yet</h3>
                <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 24 }}>
                  Add your social media accounts to start monitoring them for fraud.
                </p>
                <button onClick={() => setShowAddAccount(true)} style={{
                  padding: '11px 28px', background: 'var(--accent-blue)', border: 'none',
                  borderRadius: 8, color: '#fff', fontFamily: 'var(--font-mono)', fontSize: 14, fontWeight: 600,
                }}>Add your first account</button>
              </Card>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 16 }}>
                {accounts.map(a => (
                  <Card key={a.id} style={{ position: 'relative' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
                      <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                        <div style={{
                          width: 40, height: 40, borderRadius: 10,
                          background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                          display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 20,
                        }}>
                          {PLATFORM_ICON[a.platform] || '🌐'}
                        </div>
                        <div>
                          <div style={{ fontWeight: 700, fontSize: 14, color: 'var(--text-primary)' }}>@{a.username}</div>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'capitalize', marginTop: 2 }}>{a.platform}</div>
                        </div>
                      </div>
                      <Badge
                        label={a.status}
                        color={a.status === 'active' ? '#22c55e' : a.status === 'compromised' ? '#ff3b3b' : '#f5c842'}
                      />
                    </div>

                    {a.display_name && (
                      <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 12 }}>{a.display_name}</div>
                    )}

                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 16 }}>
                      <div style={{ background: 'var(--bg-elevated)', borderRadius: 6, padding: '7px 10px' }}>
                        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2 }}>REGISTERED</div>
                        <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{new Date(a.registered_at).toLocaleDateString()}</div>
                      </div>
                      <div style={{ background: 'var(--bg-elevated)', borderRadius: 6, padding: '7px 10px' }}>
                        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2 }}>LAST CHECKED</div>
                        <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                          {a.last_checked_at ? new Date(a.last_checked_at).toLocaleString() : '—'}
                        </div>
                      </div>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                      <button onClick={() => handleDeleteAccount(a.id)} style={{
                        padding: '5px 12px', background: '#ff3b3b10',
                        border: '1px solid #ff3b3b30', borderRadius: 6,
                        color: '#ff7070', fontFamily: 'var(--font-mono)', fontSize: 11,
                      }}>Remove</button>
                    </div>
                  </Card>
                ))}
              </div>
            )}
          </div>
        )}
      </main>

      {/* ── Modals ── */}
      {showAddAccount && (
        <AddAccountModal onClose={() => setShowAddAccount(false)} onAdded={loadAccounts} />
      )}
      {selectedAlert && (
        <AlertDetailModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onUpdate={() => { loadAlerts(); loadSummary() }}
        />
      )}

      <style>{`
        @keyframes pulse {
          0%, 100% { box-shadow: 0 0 0 3px rgba(255,59,59,0.3); }
          50% { box-shadow: 0 0 0 6px rgba(255,59,59,0.1); }
        }
      `}</style>
    </div>
  )
}
