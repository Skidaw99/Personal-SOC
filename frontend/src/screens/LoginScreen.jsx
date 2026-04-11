/**
 * Login Screen — HTTP Basic Auth.
 *
 * Particle grid canvas background, centered card,
 * shield logo, username/password, Enter key support.
 */
import { useState, useEffect, useRef } from 'react'
import { api } from '../api'

function ParticleCanvas() {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    let animId

    const resize = () => {
      canvas.width = window.innerWidth
      canvas.height = window.innerHeight
    }
    resize()
    window.addEventListener('resize', resize)

    const particles = Array.from({ length: 60 }, () => ({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      r: Math.random() * 1.5 + 0.5,
    }))

    function draw() {
      ctx.clearRect(0, 0, canvas.width, canvas.height)

      // Draw connections
      ctx.strokeStyle = 'rgba(0,212,255,0.06)'
      ctx.lineWidth = 0.5
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x
          const dy = particles[i].y - particles[j].y
          const dist = Math.sqrt(dx * dx + dy * dy)
          if (dist < 150) {
            ctx.beginPath()
            ctx.moveTo(particles[i].x, particles[i].y)
            ctx.lineTo(particles[j].x, particles[j].y)
            ctx.stroke()
          }
        }
      }

      // Draw particles
      for (const p of particles) {
        ctx.fillStyle = 'rgba(0,212,255,0.3)'
        ctx.beginPath()
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2)
        ctx.fill()

        p.x += p.vx
        p.y += p.vy
        if (p.x < 0 || p.x > canvas.width) p.vx *= -1
        if (p.y < 0 || p.y > canvas.height) p.vy *= -1
      }

      animId = requestAnimationFrame(draw)
    }
    draw()

    return () => {
      cancelAnimationFrame(animId)
      window.removeEventListener('resize', resize)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed', top: 0, left: 0,
        width: '100%', height: '100%', zIndex: 0,
      }}
    />
  )
}

export default function LoginScreen({ onLogin }) {
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    if (!user.trim() || !pass.trim()) return
    setError('')
    setLoading(true)

    localStorage.setItem('sfd_user', user.trim())
    localStorage.setItem('sfd_pass', pass.trim())

    try {
      await api.checkAuth()
      onLogin()
    } catch {
      localStorage.removeItem('sfd_user')
      localStorage.removeItem('sfd_pass')
      setError('Invalid credentials')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-screen">
      <ParticleCanvas />
      <form className="login-card" onSubmit={handleSubmit}>
        <div className="login-logo">&#9741;</div>
        <h1 className="login-title">PERSONAL SOC</h1>
        <p className="login-subtitle">SECURITY OPERATIONS CENTER</p>

        {error && <div className="login-error">{error}</div>}

        <div className="form-group">
          <label className="form-label">USERNAME</label>
          <input
            className="form-input"
            type="text"
            value={user}
            onChange={e => setUser(e.target.value)}
            autoFocus
            disabled={loading}
            autoComplete="username"
          />
        </div>

        <div className="form-group">
          <label className="form-label">PASSWORD</label>
          <input
            className="form-input"
            type="password"
            value={pass}
            onChange={e => setPass(e.target.value)}
            disabled={loading}
            autoComplete="current-password"
          />
        </div>

        <button className="btn btn-cyan login-btn" type="submit" disabled={loading}>
          {loading ? 'AUTHENTICATING...' : 'LOGIN'}
        </button>
      </form>
    </div>
  )
}
