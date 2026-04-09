/**
 * Threat State Machine — the brain of the adaptive layout.
 *
 * Four states:
 *   CALM     → default, peaceful monitoring
 *   ELEVATED → intel activity detected, feeds foregrounded
 *   ACTIVE   → live incident, takes 60% viewport
 *   CRITICAL → full takeover, red pulse, audio alert
 *
 * State transitions are driven by:
 *   1. WebSocket events (risk_score, event_type)
 *   2. Manual override by analyst
 *   3. Decay timer (auto-downgrade after inactivity)
 *
 * The state machine is a React context so every panel can read
 * the current state and adapt its layout/priority.
 */
import { createContext, useContext, useReducer, useCallback, useRef, useEffect } from 'react'

// ── States ──────────────────────────────────────────────────────────────────

export const THREAT_STATES = {
  CALM:     'CALM',
  ELEVATED: 'ELEVATED',
  ACTIVE:   'ACTIVE',
  CRITICAL: 'CRITICAL',
}

// State priority (higher = more severe)
const STATE_PRIORITY = {
  CALM: 0,
  ELEVATED: 1,
  ACTIVE: 2,
  CRITICAL: 3,
}

// Auto-decay timers (ms) — how long before downgrading
const DECAY_TIMERS = {
  CRITICAL: 120_000,  // 2 min → ACTIVE
  ACTIVE:    60_000,  // 1 min → ELEVATED
  ELEVATED:  45_000,  // 45s  → CALM
  CALM:     Infinity,
}

// ── Actions ─────────────────────────────────────────────────────────────────

const ACTIONS = {
  ESCALATE:      'ESCALATE',
  DEESCALATE:    'DEESCALATE',
  SET_STATE:     'SET_STATE',
  PUSH_EVENT:    'PUSH_EVENT',
  SET_INCIDENT:  'SET_INCIDENT',
  CLEAR_INCIDENT:'CLEAR_INCIDENT',
  PUSH_ACTOR:    'PUSH_ACTOR',
  PUSH_COPILOT:  'PUSH_COPILOT',
}

// ── Initial state ───────────────────────────────────────────────────────────

const initialState = {
  current: THREAT_STATES.CALM,
  previous: null,
  events: [],           // Recent event feed (max 100)
  activeIncident: null,  // The incident driving ACTIVE/CRITICAL state
  activeActor: null,     // Currently foregrounded threat actor
  copilotMessages: [],   // AI copilot message queue
  lastEscalation: 0,     // Timestamp of last escalation
  eventCount: 0,         // Total events since session start
}

// ── Reducer ─────────────────────────────────────────────────────────────────

function threatReducer(state, action) {
  switch (action.type) {
    case ACTIONS.SET_STATE: {
      if (state.current === action.payload) return state
      return {
        ...state,
        previous: state.current,
        current: action.payload,
        lastEscalation: Date.now(),
      }
    }

    case ACTIONS.ESCALATE: {
      const target = action.payload
      if (STATE_PRIORITY[target] <= STATE_PRIORITY[state.current]) return state
      return {
        ...state,
        previous: state.current,
        current: target,
        lastEscalation: Date.now(),
      }
    }

    case ACTIONS.DEESCALATE: {
      const target = action.payload
      if (STATE_PRIORITY[target] >= STATE_PRIORITY[state.current]) return state
      return {
        ...state,
        previous: state.current,
        current: target,
      }
    }

    case ACTIONS.PUSH_EVENT: {
      const event = action.payload
      const events = [event, ...state.events].slice(0, 100)
      return {
        ...state,
        events,
        eventCount: state.eventCount + 1,
      }
    }

    case ACTIONS.SET_INCIDENT:
      return { ...state, activeIncident: action.payload }

    case ACTIONS.CLEAR_INCIDENT:
      return { ...state, activeIncident: null }

    case ACTIONS.PUSH_ACTOR:
      return { ...state, activeActor: action.payload }

    case ACTIONS.PUSH_COPILOT: {
      const msgs = [...state.copilotMessages, action.payload].slice(-50)
      return { ...state, copilotMessages: msgs }
    }

    default:
      return state
  }
}

// ── Context ─────────────────────────────────────────────────────────────────

const ThreatStateContext = createContext(null)

export function ThreatStateProvider({ children }) {
  const [state, dispatch] = useReducer(threatReducer, initialState)
  const decayTimerRef = useRef(null)

  // ── Auto-decay: downgrade state after inactivity ──────────────────────
  useEffect(() => {
    if (decayTimerRef.current) clearTimeout(decayTimerRef.current)

    const decayMs = DECAY_TIMERS[state.current]
    if (decayMs === Infinity) return

    const downgrade = {
      CRITICAL: THREAT_STATES.ACTIVE,
      ACTIVE:   THREAT_STATES.ELEVATED,
      ELEVATED: THREAT_STATES.CALM,
    }

    decayTimerRef.current = setTimeout(() => {
      const target = downgrade[state.current]
      if (target) {
        dispatch({ type: ACTIONS.DEESCALATE, payload: target })
      }
    }, decayMs)

    return () => {
      if (decayTimerRef.current) clearTimeout(decayTimerRef.current)
    }
  }, [state.current, state.lastEscalation])

  // ── Public API ────────────────────────────────────────────────────────

  const processEvent = useCallback((event) => {
    // 1. Push to feed
    dispatch({ type: ACTIONS.PUSH_EVENT, payload: event })

    // 2. Determine state escalation based on risk_score + event_type
    const risk = event.risk_score ?? event.threat_score ?? 0
    const eventType = event.event_type ?? ''

    if (risk >= 90 || eventType === 'account_takeover') {
      dispatch({ type: ACTIONS.ESCALATE, payload: THREAT_STATES.CRITICAL })
      dispatch({ type: ACTIONS.SET_INCIDENT, payload: event })
    } else if (risk >= 70) {
      dispatch({ type: ACTIONS.ESCALATE, payload: THREAT_STATES.ACTIVE })
      dispatch({ type: ACTIONS.SET_INCIDENT, payload: event })
    } else if (risk >= 50) {
      dispatch({ type: ACTIONS.ESCALATE, payload: THREAT_STATES.ELEVATED })
    }
    // risk < 50 doesn't escalate

    // 3. If event has actor data, push actor
    if (event.actor_display_name || event.actor_id) {
      dispatch({ type: ACTIONS.PUSH_ACTOR, payload: {
        id: event.actor_id,
        display_name: event.actor_display_name,
        threat_level: event.actor_threat_level,
        ...event.actor,
      }})
    }
  }, [])

  const setThreatState = useCallback((newState) => {
    dispatch({ type: ACTIONS.SET_STATE, payload: newState })
  }, [])

  const clearIncident = useCallback(() => {
    dispatch({ type: ACTIONS.CLEAR_INCIDENT })
    dispatch({ type: ACTIONS.DEESCALATE, payload: THREAT_STATES.ELEVATED })
  }, [])

  const pushCopilotMessage = useCallback((msg) => {
    dispatch({ type: ACTIONS.PUSH_COPILOT, payload: {
      id: Date.now(),
      timestamp: new Date().toISOString(),
      ...msg,
    }})
  }, [])

  const value = {
    ...state,
    processEvent,
    setThreatState,
    clearIncident,
    pushCopilotMessage,
    // Computed
    isCritical: state.current === THREAT_STATES.CRITICAL,
    isActive:   state.current === THREAT_STATES.ACTIVE,
    isElevated: state.current === THREAT_STATES.ELEVATED,
    isCalm:     state.current === THREAT_STATES.CALM,
    stateClass: `state-${state.current.toLowerCase()}`,
  }

  return (
    <ThreatStateContext.Provider value={value}>
      {children}
    </ThreatStateContext.Provider>
  )
}

export function useThreatState() {
  const ctx = useContext(ThreatStateContext)
  if (!ctx) throw new Error('useThreatState must be used within ThreatStateProvider')
  return ctx
}
