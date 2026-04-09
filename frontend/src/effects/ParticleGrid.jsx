/**
 * Particle Grid Background — ambient animated particle field.
 *
 * Adapts to threat state:
 *   CALM:     slow drift, dim particles, wide spacing
 *   ELEVATED: faster drift, brighter, amber tint
 *   ACTIVE:   fast movement, cyan glow, connected lines
 *   CRITICAL: rapid, red particles, high density
 */
import { useRef, useEffect } from 'react'
import { useThreatState, THREAT_STATES } from '../engine/threatState'

const STATE_CONFIG = {
  [THREAT_STATES.CALM]: {
    count: 60,
    speed: 0.15,
    color: [0, 212, 255],
    opacity: 0.15,
    lineOpacity: 0.03,
    lineDist: 150,
  },
  [THREAT_STATES.ELEVATED]: {
    count: 80,
    speed: 0.3,
    color: [255, 170, 0],
    opacity: 0.25,
    lineOpacity: 0.05,
    lineDist: 130,
  },
  [THREAT_STATES.ACTIVE]: {
    count: 100,
    speed: 0.5,
    color: [0, 212, 255],
    opacity: 0.3,
    lineOpacity: 0.07,
    lineDist: 120,
  },
  [THREAT_STATES.CRITICAL]: {
    count: 120,
    speed: 0.8,
    color: [255, 0, 64],
    opacity: 0.35,
    lineOpacity: 0.08,
    lineDist: 110,
  },
}

export default function ParticleGrid() {
  const canvasRef = useRef(null)
  const { current } = useThreatState()
  const configRef = useRef(STATE_CONFIG[THREAT_STATES.CALM])
  const particlesRef = useRef([])
  const animRef = useRef(null)

  // Smoothly transition config values
  useEffect(() => {
    configRef.current = STATE_CONFIG[current] || STATE_CONFIG[THREAT_STATES.CALM]
  }, [current])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    let w, h

    function resize() {
      w = canvas.width = window.innerWidth
      h = canvas.height = window.innerHeight
    }
    resize()
    window.addEventListener('resize', resize)

    // Initialize particles
    function initParticles(count) {
      const particles = []
      for (let i = 0; i < count; i++) {
        particles.push({
          x: Math.random() * w,
          y: Math.random() * h,
          vx: (Math.random() - 0.5) * 2,
          vy: (Math.random() - 0.5) * 2,
          size: Math.random() * 1.5 + 0.5,
        })
      }
      return particles
    }
    particlesRef.current = initParticles(120) // max count

    function draw() {
      const cfg = configRef.current
      const [r, g, b] = cfg.color
      const activeCount = Math.min(cfg.count, particlesRef.current.length)

      ctx.clearRect(0, 0, w, h)

      // Update + draw particles
      for (let i = 0; i < activeCount; i++) {
        const p = particlesRef.current[i]
        p.x += p.vx * cfg.speed
        p.y += p.vy * cfg.speed

        // Wrap around
        if (p.x < 0) p.x = w
        if (p.x > w) p.x = 0
        if (p.y < 0) p.y = h
        if (p.y > h) p.y = 0

        // Draw particle
        ctx.beginPath()
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2)
        ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${cfg.opacity})`
        ctx.fill()
      }

      // Draw connection lines
      for (let i = 0; i < activeCount; i++) {
        for (let j = i + 1; j < activeCount; j++) {
          const a = particlesRef.current[i]
          const b2 = particlesRef.current[j]
          const dx = a.x - b2.x
          const dy = a.y - b2.y
          const dist = Math.sqrt(dx * dx + dy * dy)

          if (dist < cfg.lineDist) {
            const alpha = cfg.lineOpacity * (1 - dist / cfg.lineDist)
            ctx.beginPath()
            ctx.moveTo(a.x, a.y)
            ctx.lineTo(b2.x, b2.y)
            ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, ${alpha})`
            ctx.lineWidth = 0.5
            ctx.stroke()
          }
        }
      }

      animRef.current = requestAnimationFrame(draw)
    }

    draw()

    return () => {
      window.removeEventListener('resize', resize)
      if (animRef.current) cancelAnimationFrame(animRef.current)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 0,
        pointerEvents: 'none',
      }}
    />
  )
}
