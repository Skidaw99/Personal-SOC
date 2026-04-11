/**
 * Global Threat State — shared across ALL screens.
 *
 * Connects to /ws/threatcon for real-time threat level updates.
 * Polls /api/alerts/ for open alert counts.
 * NavBar and CriticalBanner consume this context.
 */
import { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react'
import { api, getAuthToken } from '../api'

const GlobalThreatContext = createContext(null)

const THREAT_COLORS = {
  CALM: 'var(--cyan)',
  ELEVATED: 'var(--amber)',
  ACTIVE: '#ff7c2a',
  CRITICAL: 'var(--red)',
}

export function GlobalThreatProvider({ children }) {
  const [threatLevel, setThreatLevel] = useState('CALM')
  const [openAlertCount, setOpenAlertCount] = useState(0)
  const [criticalAlertCount, setCriticalAlertCount] = useState(0)
  const [criticalAlert, setCriticalAlert] = useState(null)
  const wsRef = useRef(null)
  const reconnectRef = useRef(0)
  const reconnectTimer = useRef(null)
  const pollTimer = useRef(null)

  // Poll open alerts every 30s
  const pollAlerts = useCallback(async () => {
    try {
      const alerts = await api.getAlerts({ status: 'open', limit: 50 })
      if (!Array.isArray(alerts)) return
      setOpenAlertCount(alerts.length)
      const critical = alerts.filter(a => a.risk_score >= 90)
      setCriticalAlertCount(critical.length)
      setCriticalAlert(critical[0] || null)
    } catch {
      // silent — auth may have expired
    }
  }, [])

  useEffect(() => {
    pollAlerts()
    pollTimer.current = setInterval(pollAlerts, 30000)
    return () => clearInterval(pollTimer.current)
  }, [pollAlerts])

  // WebSocket /ws/threatcon
  const connectWS = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    try {
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
      const token = getAuthToken()
      const ws = new WebSocket(`${proto}//${location.host}/ws/threatcon?token=${token}`)
      wsRef.current = ws

      ws.onopen = () => { reconnectRef.current = 0 }

      ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data)
          if (msg.level) setThreatLevel(msg.level)
          if (msg.open_alerts !== undefined) setOpenAlertCount(msg.open_alerts)
        } catch { /* ignore */ }
      }

      ws.onclose = () => {
        const delay = Math.min(1000 * Math.pow(2, reconnectRef.current), 30000)
        reconnectRef.current++
        reconnectTimer.current = setTimeout(connectWS, delay)
      }

      ws.onerror = () => ws.close()
    } catch {
      const delay = Math.min(1000 * Math.pow(2, reconnectRef.current), 30000)
      reconnectRef.current++
      reconnectTimer.current = setTimeout(connectWS, delay)
    }
  }, [])

  useEffect(() => {
    connectWS()
    return () => {
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      if (wsRef.current) wsRef.current.close()
    }
  }, [connectWS])

  const value = {
    threatLevel,
    threatColor: THREAT_COLORS[threatLevel] || 'var(--text-muted)',
    openAlertCount,
    criticalAlertCount,
    criticalAlert,
    isCritical: threatLevel === 'CRITICAL',
    refreshAlerts: pollAlerts,
  }

  return (
    <GlobalThreatContext.Provider value={value}>
      {children}
    </GlobalThreatContext.Provider>
  )
}

export function useGlobalThreat() {
  const ctx = useContext(GlobalThreatContext)
  if (!ctx) throw new Error('useGlobalThreat must be used within GlobalThreatProvider')
  return ctx
}
