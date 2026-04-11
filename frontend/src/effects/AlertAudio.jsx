/**
 * Alert Audio — short 200ms alarm burst on CRITICAL state entry.
 *
 * Plays once on transition to CRITICAL, does not loop.
 * Dual-tone (440Hz + 523Hz) with fast envelope for urgency.
 */
import { useEffect, useRef } from 'react'
import { useThreatState } from '../engine/threatState'

export default function AlertAudio() {
  const { isCritical } = useThreatState()
  const prevRef = useRef(false)

  useEffect(() => {
    // Only fire on transition TO critical (not while staying critical)
    if (isCritical && !prevRef.current) {
      playBurst()
    }
    prevRef.current = isCritical
  }, [isCritical])

  function playBurst() {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)()
      const now = ctx.currentTime

      const gain = ctx.createGain()
      gain.gain.setValueAtTime(0.08, now)
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.2)
      gain.connect(ctx.destination)

      // Tone 1: A4
      const osc1 = ctx.createOscillator()
      osc1.type = 'sine'
      osc1.frequency.value = 440
      osc1.connect(gain)
      osc1.start(now)
      osc1.stop(now + 0.2)

      // Tone 2: C5 (minor urgency interval)
      const osc2 = ctx.createOscillator()
      osc2.type = 'sine'
      osc2.frequency.value = 523.25
      osc2.connect(gain)
      osc2.start(now)
      osc2.stop(now + 0.2)

      // Cleanup after burst
      osc1.onended = () => ctx.close()
    } catch {
      // Audio context unavailable — silent fail
    }
  }

  return null
}
