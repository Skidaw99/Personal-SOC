/**
 * Alert WebSocket Hook — real-time alert updates.
 *
 * Connects to /ws/alerts with auth token.
 * Same reconnection pattern as useSOCWebSocket.
 */
import { useEffect, useRef, useState, useCallback } from 'react'
import { getAuthToken } from '../api'

const RECONNECT_BASE_MS = 1000
const RECONNECT_MAX_MS = 30000

export function useAlertWebSocket(onAlert) {
  const wsRef = useRef(null)
  const reconnectAttempt = useRef(0)
  const reconnectTimer = useRef(null)
  const [connected, setConnected] = useState(false)
  const onAlertRef = useRef(onAlert)
  onAlertRef.current = onAlert

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    try {
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
      const token = getAuthToken()
      const ws = new WebSocket(`${proto}//${location.host}/ws/alerts?token=${token}`)
      wsRef.current = ws

      ws.onopen = () => {
        setConnected(true)
        reconnectAttempt.current = 0
      }

      ws.onmessage = (evt) => {
        try {
          const data = JSON.parse(evt.data)
          onAlertRef.current?.(data)
        } catch { /* ignore */ }
      }

      ws.onclose = () => {
        setConnected(false)
        scheduleReconnect()
      }

      ws.onerror = () => ws.close()
    } catch {
      scheduleReconnect()
    }
  }, [])

  const scheduleReconnect = useCallback(() => {
    if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
    const delay = Math.min(RECONNECT_BASE_MS * Math.pow(2, reconnectAttempt.current), RECONNECT_MAX_MS)
    reconnectAttempt.current++
    reconnectTimer.current = setTimeout(connect, delay)
  }, [connect])

  useEffect(() => {
    connect()
    return () => {
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      if (wsRef.current) wsRef.current.close()
    }
  }, [connect])

  return { connected }
}
