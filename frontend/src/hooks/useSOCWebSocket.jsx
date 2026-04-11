/**
 * SOC WebSocket Hook — real-time event stream from the orchestrator.
 *
 * Connects to the SOC WebSocket endpoint and pushes events
 * into the threat state machine. Handles reconnection with
 * exponential backoff.
 *
 * Message format expected:
 *   { type: "event"|"alert"|"actor"|"copilot", data: {...} }
 */
import { useEffect, useRef, useState, useCallback } from 'react'
import { useThreatState } from '../engine/threatState'

function getWSUrl() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  const user = localStorage.getItem('sfd_user') || ''
  const pass = localStorage.getItem('sfd_pass') || ''
  const token = btoa(`${user}:${pass}`)
  return `${proto}//${location.host}/ws/soc?token=${token}`
}
const RECONNECT_BASE_MS = 1000
const RECONNECT_MAX_MS = 30000

export function useSOCWebSocket() {
  const { processEvent, pushCopilotMessage } = useThreatState()
  const wsRef = useRef(null)
  const reconnectAttempt = useRef(0)
  const reconnectTimer = useRef(null)
  const [connected, setConnected] = useState(false)

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    try {
      const ws = new WebSocket(getWSUrl())
      wsRef.current = ws

      ws.onopen = () => {
        setConnected(true)
        reconnectAttempt.current = 0
      }

      ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data)
          switch (msg.type) {
            case 'event':
            case 'alert':
              processEvent(msg.data)
              break

            case 'actor':
              processEvent({
                ...msg.data,
                event_type: 'actor_update',
                risk_score: msg.data.threat_level === 'critical' ? 90
                  : msg.data.threat_level === 'high' ? 75
                  : msg.data.threat_level === 'medium' ? 55
                  : 30,
              })
              break

            case 'copilot':
              pushCopilotMessage(msg.data)
              break

            default:
              // Unknown message type — treat as event
              if (msg.data) processEvent(msg.data)
          }
        } catch {
          // Malformed message — ignore
        }
      }

      ws.onclose = () => {
        setConnected(false)
        scheduleReconnect()
      }

      ws.onerror = () => {
        ws.close()
      }
    } catch {
      scheduleReconnect()
    }
  }, [processEvent, pushCopilotMessage])

  const scheduleReconnect = useCallback(() => {
    if (reconnectTimer.current) clearTimeout(reconnectTimer.current)

    const delay = Math.min(
      RECONNECT_BASE_MS * Math.pow(2, reconnectAttempt.current),
      RECONNECT_MAX_MS,
    )
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
