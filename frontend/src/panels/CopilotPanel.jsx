/**
 * AI Copilot Panel — persistent chat with the SOC AI.
 *
 * - Proactive alerts on new incidents
 * - Large input field in CRITICAL state
 * - Messages: AI bubbles left, user bubbles right
 * - Auto-scroll, loading indicator
 */
import { useState, useRef, useEffect } from 'react'
import Panel from './Panel'
import { PANELS } from '../engine/layoutEngine'
import { useThreatState } from '../engine/threatState'

function Message({ msg }) {
  const isAI = msg.role === 'assistant' || msg.role === 'system'
  const isAlert = msg.type === 'alert' || msg.type === 'proactive'

  return (
    <div className="fade-in" style={{
      display: 'flex', flexDirection: 'column',
      alignItems: isAI ? 'flex-start' : 'flex-end',
      marginBottom: 10,
    }}>
      <span style={{
        fontFamily: 'var(--font-display)', fontSize: 9,
        letterSpacing: '2px', textTransform: 'uppercase',
        color: isAI ? 'var(--cyan)' : 'var(--text-muted)',
        marginBottom: 3,
      }}>
        {isAI ? 'AI COPILOT' : 'YOU'}
      </span>

      <div style={{
        maxWidth: '92%',
        padding: '10px 14px',
        borderRadius: 8,
        fontSize: 14,
        lineHeight: 1.6,
        fontFamily: 'var(--font-mono)',
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
        background: isAlert ? 'var(--red-dim)' : isAI ? 'rgba(0,212,255,0.04)' : 'rgba(255,255,255,0.04)',
        border: `1px solid ${isAlert ? 'var(--border-danger)' : 'var(--border)'}`,
        color: isAlert ? 'var(--red)' : 'var(--text-primary)',
      }}>
        {msg.content || msg.message || msg.text}
      </div>

      <span style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
        {msg.timestamp ? new Date(msg.timestamp).toLocaleTimeString('en-GB', { hour12: false }) : ''}
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

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight
  }, [copilotMessages.length])

  // Proactive alert on new incident
  useEffect(() => {
    if (activeIncident && Date.now() - lastProactiveRef.current > 5000) {
      lastProactiveRef.current = Date.now()
      const risk = activeIncident.risk_score ?? 0
      const type = (activeIncident.event_type || 'unknown').replace(/_/g, ' ')
      const ip = activeIncident.source_ip || 'unknown IP'
      const actor = activeIncident.actor_display_name

      pushCopilotMessage({
        role: 'assistant',
        type: risk >= 90 ? 'proactive' : 'alert',
        content: risk >= 90
          ? `Critical threat detected — ${type} from ${ip}${actor ? ` (actor: ${actor})` : ''}. Risk: ${risk.toFixed(0)}/100.\n\nAutomated response initiated. IP flagged for blocking. Full enrichment running.`
          : `New ${type} detected from ${ip}. Risk: ${risk.toFixed(0)}/100. Monitoring for escalation.`,
      })
    }
  }, [activeIncident, pushCopilotMessage])

  async function handleSend(e) {
    e.preventDefault()
    if (!input.trim() || loading) return

    const userMsg = input.trim()
    setInput('')
    pushCopilotMessage({ role: 'user', content: userMsg })
    setLoading(true)

    try {
      const res = await fetch('/api/soc/ai/chat', {
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
          role: 'assistant', type: 'alert',
          content: 'AI backend connection failed.',
        })
      }
    } catch {
      pushCopilotMessage({
        role: 'assistant', type: 'alert',
        content: 'Network error. AI copilot temporarily unavailable.',
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <Panel
      panelId={PANELS.COPILOT}
      title="AI COPILOT"
      icon="&#9672;"
      status={loading ? 'ANALYZING...' : undefined}
    >
      <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
        {/* Messages */}
        <div ref={scrollRef} style={{
          flex: 1, overflowY: 'auto', overflowX: 'hidden',
          paddingRight: 4, marginBottom: 8,
        }}>
          {copilotMessages.length === 0 ? (
            <div style={{
              display: 'flex', flexDirection: 'column', alignItems: 'center',
              justifyContent: 'center', height: '100%', gap: 8,
              color: 'var(--text-muted)', textAlign: 'center',
            }}>
              <span style={{ fontSize: 24 }}>&#9672;</span>
              <span style={{
                fontFamily: 'var(--font-display)', fontSize: 11,
                letterSpacing: '2px',
              }}>
                AI COPILOT READY
              </span>
              <span style={{ fontSize: 12 }}>
                Ask about threats, IPs, or incidents
              </span>
            </div>
          ) : (
            copilotMessages.map(msg => (
              <Message key={msg.id || Math.random()} msg={msg} />
            ))
          )}

          {loading && (
            <div style={{
              fontFamily: 'var(--font-display)', fontSize: 11,
              letterSpacing: '2px', color: 'var(--cyan)',
              padding: '4px 0',
            }}>
              &#9672; ANALYZING...
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
              padding: isCritical ? '12px 14px' : '8px 12px',
              background: 'rgba(255,255,255,0.03)',
              border: `1px solid ${isCritical ? 'var(--border-danger)' : 'var(--border)'}`,
              borderRadius: 6,
              color: 'var(--text-primary)',
              fontFamily: 'var(--font-mono)',
              fontSize: 14,
              outline: 'none',
              transition: 'padding 300ms ease, border-color 200ms ease',
            }}
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            style={{
              padding: '8px 16px',
              background: 'var(--cyan-dim)',
              border: '1px solid var(--border-active)',
              borderRadius: 6,
              color: 'var(--cyan)',
              fontFamily: 'var(--font-display)',
              fontSize: 10,
              fontWeight: 600,
              letterSpacing: '1.5px',
              opacity: loading || !input.trim() ? 0.3 : 1,
              transition: 'opacity 200ms ease',
            }}
          >
            SEND
          </button>
        </form>
      </div>
    </Panel>
  )
}
