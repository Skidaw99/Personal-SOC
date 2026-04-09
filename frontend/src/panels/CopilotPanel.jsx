/**
 * AI Copilot Panel — persistent chat with the AI copilot.
 *
 * Features:
 * - Proactive messages from AI (pushed via WebSocket/state machine)
 * - Chat input for analyst questions
 * - Auto-generated alerts for critical events
 * - Markdown-formatted responses
 *
 * Always visible, always reachable. Expands in higher threat states.
 */
import { useState, useRef, useEffect } from 'react'
import Panel from './Panel'
import { PANELS } from '../engine/layoutEngine'
import { useThreatState } from '../engine/threatState'

function Message({ msg }) {
  const isAI = msg.role === 'assistant' || msg.role === 'system'
  const isAlert = msg.type === 'alert' || msg.type === 'proactive'

  return (
    <div
      className="fade-in"
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: isAI ? 'flex-start' : 'flex-end',
        marginBottom: 8,
      }}
    >
      {/* Sender label */}
      <span style={{
        fontSize: '0.55rem',
        color: isAI ? 'var(--cyan)' : 'var(--text-muted)',
        fontFamily: 'var(--font-display)',
        letterSpacing: '0.08em',
        textTransform: 'uppercase',
        marginBottom: 2,
      }}>
        {isAI ? 'AI COPILOT' : 'YOU'}
      </span>

      {/* Message bubble */}
      <div style={{
        maxWidth: '90%',
        padding: '8px 12px',
        borderRadius: 8,
        fontSize: '0.75rem',
        lineHeight: 1.5,
        background: isAlert
          ? 'var(--red-dim)'
          : isAI
            ? 'rgba(0, 212, 255, 0.06)'
            : 'rgba(255, 255, 255, 0.06)',
        border: `1px solid ${
          isAlert ? 'var(--border-danger)' : 'var(--border)'
        }`,
        color: isAlert ? 'var(--red)' : 'var(--text-primary)',
        fontFamily: 'var(--font-mono)',
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
      }}>
        {msg.content || msg.message || msg.text}
      </div>

      {/* Timestamp */}
      <span style={{
        fontSize: '0.5rem',
        color: 'var(--text-muted)',
        marginTop: 2,
      }}>
        {msg.timestamp
          ? new Date(msg.timestamp).toLocaleTimeString('en-GB', { hour12: false })
          : ''
        }
      </span>
    </div>
  )
}

export default function CopilotPanel() {
  const { copilotMessages, activeIncident, pushCopilotMessage, isCritical } = useThreatState()
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const scrollRef = useRef(null)
  const lastProactiveRef = useRef(0)

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [copilotMessages.length])

  // Proactive alert when incident arrives
  useEffect(() => {
    if (activeIncident && Date.now() - lastProactiveRef.current > 5000) {
      lastProactiveRef.current = Date.now()
      const risk = activeIncident.risk_score ?? 0
      const type = (activeIncident.event_type || 'unknown').replace(/_/g, ' ')
      const ip = activeIncident.source_ip || 'unknown IP'

      pushCopilotMessage({
        role: 'assistant',
        type: 'proactive',
        content: `⚠ New ${type} detected from ${ip} — risk score ${risk.toFixed(0)}/100. ${
          risk >= 90
            ? 'CRITICAL: Automated response initiated. IP block + alert deployed.'
            : risk >= 70
              ? 'HIGH RISK: Review recommended. Webhook alert sent.'
              : 'Monitoring. Will escalate if pattern continues.'
        }`,
      })
    }
  }, [activeIncident, pushCopilotMessage])

  async function handleSend(e) {
    e.preventDefault()
    if (!input.trim() || loading) return

    const userMsg = input.trim()
    setInput('')

    pushCopilotMessage({
      role: 'user',
      content: userMsg,
    })

    setLoading(true)

    try {
      const res = await fetch('/api/soc/copilot/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: userMsg,
          risk_score: activeIncident?.risk_score || 0,
          context: activeIncident || undefined,
        }),
      })

      if (res.ok) {
        const data = await res.json()
        pushCopilotMessage({
          role: 'assistant',
          content: data.content || 'No response.',
          model: data.model_used,
          backend: data.backend_used,
        })
      } else {
        pushCopilotMessage({
          role: 'assistant',
          content: 'Connection to AI backend failed. Retrying...',
          type: 'alert',
        })
      }
    } catch {
      pushCopilotMessage({
        role: 'assistant',
        content: 'Network error. AI copilot temporarily unavailable.',
        type: 'alert',
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <Panel panelId={PANELS.COPILOT} title="AI COPILOT" icon="◈">
      <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
        {/* Messages */}
        <div
          ref={scrollRef}
          style={{
            flex: 1,
            overflowY: 'auto',
            overflowX: 'hidden',
            paddingRight: 4,
            marginBottom: 8,
          }}
        >
          {copilotMessages.length === 0 ? (
            <div style={{
              display: 'flex', flexDirection: 'column', alignItems: 'center',
              justifyContent: 'center', height: '100%', gap: 8,
              color: 'var(--text-muted)', textAlign: 'center',
            }}>
              <span style={{ fontSize: '1.5rem' }}>◈</span>
              <span style={{ fontSize: '0.65rem', fontFamily: 'var(--font-display)', letterSpacing: '0.08em' }}>
                AI COPILOT READY
              </span>
              <span style={{ fontSize: '0.65rem' }}>
                Ask me anything about threats, IPs, or incidents
              </span>
            </div>
          ) : (
            copilotMessages.map(msg => (
              <Message key={msg.id || Math.random()} msg={msg} />
            ))
          )}

          {loading && (
            <div style={{
              fontSize: '0.65rem', color: 'var(--cyan)',
              fontFamily: 'var(--font-display)', letterSpacing: '0.08em',
              padding: '4px 0',
            }}>
              ◈ ANALYZING...
            </div>
          )}
        </div>

        {/* Input */}
        <form onSubmit={handleSend} style={{ display: 'flex', gap: 6 }}>
          <input
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder="Ask the copilot..."
            disabled={loading}
            style={{
              flex: 1,
              padding: '8px 12px',
              background: 'rgba(255,255,255,0.04)',
              border: `1px solid ${isCritical ? 'var(--border-danger)' : 'var(--border)'}`,
              borderRadius: 6,
              color: 'var(--text-primary)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.75rem',
              outline: 'none',
            }}
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            style={{
              padding: '8px 14px',
              background: 'var(--cyan-dim)',
              border: '1px solid var(--border-active)',
              borderRadius: 6,
              color: 'var(--cyan)',
              fontFamily: 'var(--font-display)',
              fontSize: '0.6rem',
              fontWeight: 600,
              letterSpacing: '0.08em',
              opacity: loading || !input.trim() ? 0.4 : 1,
            }}
          >
            SEND
          </button>
        </form>
      </div>
    </Panel>
  )
}
