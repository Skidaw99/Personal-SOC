/**
 * Alert Audio — Web Audio API alert tone for CRITICAL state.
 *
 * Plays a pulsing alert tone when entering CRITICAL state.
 * Automatically stops when leaving CRITICAL.
 * Requires user interaction first (browser autoplay policy).
 */
import { useEffect, useRef } from 'react'
import { useThreatState } from '../engine/threatState'

export default function AlertAudio() {
  const { isCritical } = useThreatState()
  const ctxRef = useRef(null)
  const oscRef = useRef(null)
  const gainRef = useRef(null)
  const lfoRef = useRef(null)
  const activeRef = useRef(false)

  useEffect(() => {
    if (isCritical && !activeRef.current) {
      startAlert()
    } else if (!isCritical && activeRef.current) {
      stopAlert()
    }

    return () => { stopAlert() }
  }, [isCritical])

  function startAlert() {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)()
      ctxRef.current = ctx

      // Main oscillator — dual tone (400Hz + 500Hz for urgency)
      const osc1 = ctx.createOscillator()
      osc1.type = 'sine'
      osc1.frequency.value = 440

      const osc2 = ctx.createOscillator()
      osc2.type = 'sine'
      osc2.frequency.value = 523.25 // C5

      // LFO for pulsing effect
      const lfo = ctx.createOscillator()
      lfo.type = 'sine'
      lfo.frequency.value = 2 // 2 pulses per second
      lfoRef.current = lfo

      const lfoGain = ctx.createGain()
      lfoGain.gain.value = 0.04 // Subtle volume

      const masterGain = ctx.createGain()
      masterGain.gain.value = 0.06
      gainRef.current = masterGain

      // Connect: oscs → masterGain → destination
      //          lfo → lfoGain → masterGain.gain
      osc1.connect(masterGain)
      osc2.connect(masterGain)
      lfo.connect(lfoGain)
      lfoGain.connect(masterGain.gain)
      masterGain.connect(ctx.destination)

      osc1.start()
      osc2.start()
      lfo.start()
      oscRef.current = [osc1, osc2]
      activeRef.current = true
    } catch {
      // Audio context not available — silent fail
    }
  }

  function stopAlert() {
    try {
      if (oscRef.current) {
        oscRef.current.forEach(o => { try { o.stop() } catch {} })
        oscRef.current = null
      }
      if (lfoRef.current) {
        try { lfoRef.current.stop() } catch {}
        lfoRef.current = null
      }
      if (ctxRef.current) {
        ctxRef.current.close()
        ctxRef.current = null
      }
    } catch {}
    activeRef.current = false
  }

  // Invisible component — audio only
  return null
}
