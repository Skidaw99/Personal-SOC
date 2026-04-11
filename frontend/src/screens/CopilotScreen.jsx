/**
 * Copilot Screen — full-screen AI chat interface.
 *
 * Left panel: context selector + quick actions.
 * Right: chat history + input bar.
 * sessionStorage persistence. Enter=send, Shift+Enter=newline.
 */
import { useState, useEffect, useRef, useCallback } from 'react'
import { api } from '../api'

const SHORTCUTS = [
  { label: 'Analyze latest threat', message: 'Analyze the latest critical security threat. What happened, what is the impact, and what should I do?' },
  { label: 'Summarize open alerts', message: 'Give me a summary of all currently open alerts. Group them by severity and category.' },
  { label: 'What should I do now?', message: 'Based on the current threat landscape, what actions should I prioritize right now as a SOC analyst?' },
  { label: 'Generate FBI report', message: 'Generate a formal FBI IC3 report for the most critical active threat actor.' },
  { label: 'Explain attack pattern', message: 'Explain the attack patterns I am currently seeing. Are they related? What is the likely goal of the attacker?' },
]

const CONTEXTS = [
  { key: 'general', label: 'General' },
  { key: 'critical', label: 'Latest critical alert' },
  { key: 'actor', label: 'Specific actor' },
  { key: 'alert', label: 'Specific alert' },
]

function ChatMessage({ msg }) {
  const isAI = msg.role === 'assistant'
  return (
    <div className={`chat-message ${isAI ? 'chat-message-ai' : 'chat-message-user'}`}>
      <div className="chat-message-header">
        <span className="chat-message-role">{isAI ? 'AI COPILOT' : 'YOU'}</span>
        {isAI && msg.backend && (
          <span className="chat-provider-badge">{msg.backend.toUpperCase()}</span>
        )}
        <span className="chat-message-time">
          {msg.timestamp ? new Date(msg.timestamp).toLocaleTimeString('en-GB', { hour12: false }) : ''}
        </span>
      </div>
      <div className="chat-message-body">{msg.content}</div>
    </div>
  )
}

export default function CopilotScreen() {
  const [messages, setMessages] = useState(() => {
    try {
      const saved = sessionStorage.getItem('soc_copilot_messages')
      return saved ? JSON.parse(saved) : []
    } catch { return [] }
  })
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [context, setContext] = useState('general')
  const [actors, setActors] = useState([])
  const [alerts, setAlerts] = useState([])
  const [selectedActorId, setSelectedActorId] = useState('')
  const [selectedAlertId, setSelectedAlertId] = useState('')
  const scrollRef = useRef(null)

  // Save messages to sessionStorage
  useEffect(() => {
    sessionStorage.setItem('soc_copilot_messages', JSON.stringify(messages))
  }, [messages])

  // Auto-scroll
  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight
  }, [messages.length, loading])

  // Load actors and alerts for context selectors
  useEffect(() => {
    api.getActors().then(d => setActors(d || [])).catch(() => {})
    api.getAlerts({ status: 'open', limit: 20 }).then(d => setAlerts(d || [])).catch(() => {})
  }, [])

  const sendMessage = useCallback(async (text) => {
    const msg = (text || input).trim()
    if (!msg || loading) return

    const userMsg = { role: 'user', content: msg, timestamp: new Date().toISOString() }
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setLoading(true)

    // Build context data
    let contextData = null
    if (context === 'actor' && selectedActorId) {
      const actor = actors.find(a => a.id === selectedActorId)
      if (actor) contextData = { type: 'actor', ...actor }
    } else if (context === 'alert' && selectedAlertId) {
      const alert = alerts.find(a => a.id === selectedAlertId)
      if (alert) contextData = { type: 'alert', ...alert }
    } else if (context === 'critical') {
      const critical = alerts.find(a => a.risk_score >= 90) || alerts[0]
      if (critical) contextData = { type: 'critical_alert', ...critical }
    }

    try {
      const result = await api.aiChat(msg, 0, contextData)
      const aiMsg = {
        role: 'assistant',
        content: result.content || 'No response.',
        backend: result.backend_used,
        model: result.model_used,
        timestamp: new Date().toISOString(),
      }
      setMessages(prev => [...prev, aiMsg])
    } catch (err) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: `Error: ${err.message}`,
        timestamp: new Date().toISOString(),
      }])
    } finally {
      setLoading(false)
    }
  }, [input, loading, context, selectedActorId, selectedAlertId, actors, alerts])

  function handleKeyDown(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage()
    }
  }

  function clearHistory() {
    setMessages([])
    sessionStorage.removeItem('soc_copilot_messages')
  }

  return (
    <div className="screen copilot-screen">
      {/* Left panel — context + shortcuts */}
      <div className="copilot-sidebar">
        <h3 className="section-title">CONTEXT</h3>
        <div className="copilot-context-list">
          {CONTEXTS.map(c => (
            <button
              key={c.key}
              className={`copilot-context-btn ${context === c.key ? 'copilot-context-active' : ''}`}
              onClick={() => setContext(c.key)}
            >
              {c.label}
            </button>
          ))}
        </div>

        {context === 'actor' && (
          <div className="form-group" style={{ marginTop: 8 }}>
            <select className="form-input form-select" value={selectedActorId} onChange={e => setSelectedActorId(e.target.value)}>
              <option value="">Select actor...</option>
              {actors.map(a => <option key={a.id} value={a.id}>{a.display_name}</option>)}
            </select>
          </div>
        )}

        {context === 'alert' && (
          <div className="form-group" style={{ marginTop: 8 }}>
            <select className="form-input form-select" value={selectedAlertId} onChange={e => setSelectedAlertId(e.target.value)}>
              <option value="">Select alert...</option>
              {alerts.map(a => <option key={a.id} value={a.id}>{a.title || a.category}</option>)}
            </select>
          </div>
        )}

        <h3 className="section-title" style={{ marginTop: 20 }}>QUICK ACTIONS</h3>
        <div className="copilot-shortcuts">
          {SHORTCUTS.map((s, i) => (
            <button
              key={i}
              className="copilot-shortcut-btn"
              onClick={() => sendMessage(s.message)}
              disabled={loading}
            >
              {s.label}
            </button>
          ))}
        </div>

        <button className="btn btn-muted btn-sm" style={{ marginTop: 'auto' }} onClick={clearHistory}>
          CLEAR HISTORY
        </button>
      </div>

      {/* Right — chat area */}
      <div className="copilot-chat">
        {/* Messages */}
        <div className="copilot-messages" ref={scrollRef}>
          {messages.length === 0 ? (
            <div className="copilot-empty">
              <span style={{ fontSize: 28 }}>&#9672;</span>
              <span className="section-title">AI COPILOT READY</span>
              <span className="text-muted">Ask about threats, analyze alerts, or generate reports</span>
            </div>
          ) : (
            messages.map((msg, i) => <ChatMessage key={i} msg={msg} />)
          )}
          {loading && (
            <div className="chat-message chat-message-ai">
              <div className="chat-message-body" style={{ color: 'var(--cyan)' }}>
                &#9672; ANALYZING...
              </div>
            </div>
          )}
        </div>

        {/* Input */}
        <div className="copilot-input-bar">
          <div className="copilot-input-wrapper">
            <textarea
              className="form-input copilot-textarea"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask the copilot..."
              disabled={loading}
              rows={2}
            />
            <span className="copilot-char-count">{input.length}</span>
          </div>
          <button
            className="btn btn-cyan copilot-send"
            onClick={() => sendMessage()}
            disabled={loading || !input.trim()}
          >
            SEND
          </button>
        </div>
      </div>
    </div>
  )
}
