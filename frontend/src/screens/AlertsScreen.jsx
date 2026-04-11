/**
 * Alerts Screen — alert management.
 *
 * Filter bar, alerts table, ACK/RESOLVE/FP actions,
 * detail slide-in panel, real-time WebSocket, pagination.
 */
import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'
import { useAlertWebSocket } from '../hooks/useAlertWebSocket'
import { useGlobalThreat } from '../hooks/useThreatState'

const STATUS_OPTIONS = [
  { value: '', label: 'ALL' },
  { value: 'open', label: 'OPEN' },
  { value: 'acknowledged', label: 'ACKNOWLEDGED' },
  { value: 'resolved', label: 'RESOLVED' },
  { value: 'false_positive', label: 'FALSE POSITIVE' },
]

const CATEGORY_OPTIONS = [
  { value: '', label: 'ALL' },
  { value: 'unauthorized_login', label: 'UNAUTHORIZED LOGIN' },
  { value: 'account_takeover', label: 'ACCOUNT TAKEOVER' },
  { value: 'api_token_misuse', label: 'TOKEN MISUSE' },
  { value: 'suspicious_activity', label: 'SUSPICIOUS' },
]

const STATUS_COLORS = {
  open: 'var(--amber)',
  acknowledged: 'var(--cyan)',
  resolved: 'var(--green)',
  false_positive: 'var(--text-muted)',
}

function riskColor(s) {
  if (s >= 90) return 'var(--red)'
  if (s >= 70) return '#ff7c2a'
  if (s >= 50) return 'var(--amber)'
  return 'var(--cyan)'
}

export default function AlertsScreen() {
  const { refreshAlerts } = useGlobalThreat()
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filters, setFilters] = useState({ status: '', category: '' })
  const [offset, setOffset] = useState(0)
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [notes, setNotes] = useState('')
  const [actionLoading, setActionLoading] = useState(false)
  const limit = 50

  const fetchAlerts = useCallback(async () => {
    try {
      const data = await api.getAlerts({
        ...filters,
        limit,
        offset,
      })
      setAlerts(data || [])
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [filters, offset])

  useEffect(() => { fetchAlerts() }, [fetchAlerts])

  // Real-time alert updates
  const handleAlertWS = useCallback((data) => {
    if (data?.data) {
      setAlerts(prev => {
        const existing = prev.findIndex(a => a.id === data.data.id)
        if (existing >= 0) {
          const updated = [...prev]
          updated[existing] = { ...updated[existing], ...data.data }
          return updated
        }
        return [data.data, ...prev]
      })
    }
  }, [])

  useAlertWebSocket(handleAlertWS)

  async function handleAck(id) {
    setActionLoading(true)
    try {
      await api.ackAlert(id, notes || null)
      await fetchAlerts()
      refreshAlerts()
      if (selectedAlert?.id === id) setSelectedAlert(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setActionLoading(false)
    }
  }

  async function handleResolve(id) {
    setActionLoading(true)
    try {
      await api.resolveAlert(id, { status: 'resolved', notes: notes || null })
      await fetchAlerts()
      refreshAlerts()
      if (selectedAlert?.id === id) setSelectedAlert(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setActionLoading(false)
    }
  }

  async function handleFP(id) {
    setActionLoading(true)
    try {
      await api.resolveAlert(id, { status: 'false_positive', notes: notes || null })
      await fetchAlerts()
      refreshAlerts()
      if (selectedAlert?.id === id) setSelectedAlert(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setActionLoading(false)
    }
  }

  function updateFilter(key, value) {
    setFilters(prev => ({ ...prev, [key]: value }))
    setOffset(0)
  }

  if (loading) {
    return <div className="screen screen-center"><span className="loading-text">LOADING ALERTS...</span></div>
  }

  return (
    <div className="screen">
      <h2 className="screen-title">ALERT MANAGEMENT</h2>

      {error && <div className="error-card" style={{ marginBottom: 12 }}><span className="error-text">{error}</span></div>}

      {/* Filter bar */}
      <div className="filter-bar">
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label">STATUS</label>
          <select className="form-input form-select" value={filters.status} onChange={e => updateFilter('status', e.target.value)}>
            {STATUS_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label">CATEGORY</label>
          <select className="form-input form-select" value={filters.category} onChange={e => updateFilter('category', e.target.value)}>
            {CATEGORY_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
        <span className="filter-count">{alerts.length} results</span>
      </div>

      <div style={{ display: 'flex', gap: 0, flex: 1, minHeight: 0 }}>
        {/* Table */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {alerts.length === 0 ? (
            <div className="empty-state">NO ALERTS FOUND</div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>RISK</th>
                  <th>CATEGORY</th>
                  <th>TITLE</th>
                  <th>STATUS</th>
                  <th>CREATED</th>
                  <th>ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map(alert => (
                  <tr
                    key={alert.id}
                    className={selectedAlert?.id === alert.id ? 'row-selected' : ''}
                    onClick={() => { setSelectedAlert(alert); setNotes(alert.notes || '') }}
                    style={{ cursor: 'pointer' }}
                  >
                    <td>
                      <span className="risk-badge" style={{ color: riskColor(alert.risk_score), borderColor: riskColor(alert.risk_score) }}>
                        {(alert.risk_score || 0).toFixed(0)}
                      </span>
                    </td>
                    <td className="text-upper">{(alert.category || '').replace(/_/g, ' ')}</td>
                    <td>{alert.title || 'Untitled'}</td>
                    <td>
                      <span className="status-badge" style={{ color: STATUS_COLORS[alert.status] || 'var(--text-muted)', borderColor: STATUS_COLORS[alert.status] || 'var(--border)' }}>
                        {(alert.status || 'unknown').toUpperCase()}
                      </span>
                    </td>
                    <td className="text-muted text-mono text-sm">
                      {alert.created_at ? new Date(alert.created_at).toLocaleString('en-GB', { hour12: false }) : ''}
                    </td>
                    <td onClick={e => e.stopPropagation()}>
                      {alert.status === 'open' && (
                        <div style={{ display: 'flex', gap: 4 }}>
                          <button className="btn btn-cyan btn-sm" onClick={() => handleAck(alert.id)} disabled={actionLoading}>ACK</button>
                          <button className="btn btn-muted btn-sm" onClick={() => handleResolve(alert.id)} disabled={actionLoading}>RESOLVE</button>
                          <button className="btn btn-muted btn-sm" onClick={() => handleFP(alert.id)} disabled={actionLoading}>FP</button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {/* Pagination */}
          <div className="pagination">
            <button className="btn btn-muted btn-sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}>
              PREV
            </button>
            <span className="text-muted text-sm">
              {offset + 1}–{offset + alerts.length}
            </span>
            <button className="btn btn-muted btn-sm" disabled={alerts.length < limit} onClick={() => setOffset(offset + limit)}>
              NEXT
            </button>
          </div>
        </div>

        {/* Detail panel */}
        {selectedAlert && (
          <div className="alert-detail-panel">
            <div className="alert-detail-header">
              <h3 className="alert-detail-title">{selectedAlert.title || 'Untitled'}</h3>
              <button className="btn btn-muted btn-sm" onClick={() => setSelectedAlert(null)}>&#10005;</button>
            </div>

            <div className="alert-detail-risk">
              <span style={{ color: riskColor(selectedAlert.risk_score), fontSize: 36, fontFamily: 'var(--font-display)', fontWeight: 700 }}>
                {(selectedAlert.risk_score || 0).toFixed(0)}
              </span>
              <span className="text-muted">RISK SCORE</span>
            </div>

            <div className="alert-detail-grid">
              <span className="form-label">CATEGORY</span>
              <span className="text-upper">{(selectedAlert.category || '').replace(/_/g, ' ')}</span>

              <span className="form-label">STATUS</span>
              <span style={{ color: STATUS_COLORS[selectedAlert.status] }}>
                {(selectedAlert.status || '').toUpperCase()}
              </span>

              <span className="form-label">CREATED</span>
              <span className="text-mono text-sm">
                {selectedAlert.created_at ? new Date(selectedAlert.created_at).toLocaleString('en-GB', { hour12: false }) : ''}
              </span>

              {selectedAlert.acknowledged_at && (
                <>
                  <span className="form-label">ACKNOWLEDGED</span>
                  <span className="text-mono text-sm">{new Date(selectedAlert.acknowledged_at).toLocaleString('en-GB', { hour12: false })}</span>
                </>
              )}

              {selectedAlert.resolved_at && (
                <>
                  <span className="form-label">RESOLVED</span>
                  <span className="text-mono text-sm">{new Date(selectedAlert.resolved_at).toLocaleString('en-GB', { hour12: false })}</span>
                </>
              )}
            </div>

            {selectedAlert.description && (
              <div className="alert-detail-section">
                <span className="form-label">DESCRIPTION</span>
                <p className="alert-detail-text">{selectedAlert.description}</p>
              </div>
            )}

            {selectedAlert.recommended_action && (
              <div className="alert-detail-section">
                <span className="form-label">RECOMMENDED ACTION</span>
                <p className="alert-detail-text">{selectedAlert.recommended_action}</p>
              </div>
            )}

            {selectedAlert.evidence && (
              <div className="alert-detail-section">
                <span className="form-label">EVIDENCE</span>
                <pre className="alert-detail-json">{typeof selectedAlert.evidence === 'string' ? selectedAlert.evidence : JSON.stringify(selectedAlert.evidence, null, 2)}</pre>
              </div>
            )}

            <div className="alert-detail-badges">
              {selectedAlert.email_sent && <span className="status-badge" style={{ color: 'var(--green)', borderColor: 'var(--green)' }}>EMAIL SENT</span>}
              {selectedAlert.webhook_sent && <span className="status-badge" style={{ color: 'var(--green)', borderColor: 'var(--green)' }}>WEBHOOK SENT</span>}
            </div>

            {selectedAlert.status === 'open' && (
              <div className="alert-detail-actions">
                <div className="form-group">
                  <label className="form-label">NOTES</label>
                  <textarea className="form-input form-textarea" value={notes} onChange={e => setNotes(e.target.value)} rows={3} />
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="btn btn-cyan" onClick={() => handleAck(selectedAlert.id)} disabled={actionLoading}>ACKNOWLEDGE</button>
                  <button className="btn btn-muted" onClick={() => handleResolve(selectedAlert.id)} disabled={actionLoading}>RESOLVE</button>
                  <button className="btn btn-red" onClick={() => handleFP(selectedAlert.id)} disabled={actionLoading}>FALSE POSITIVE</button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
