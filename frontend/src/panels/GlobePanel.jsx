/**
 * Globe Panel — Three.js earth with continent outlines, attack arcs, stars.
 *
 * - Wireframe sphere with lat/lng grid
 * - Continent coastline outlines
 * - NL home base — large pulsing cyan dot
 * - Attacker dots — 8px red, individual pulse
 * - Gradient arcs: red → orange → cyan
 * - Atmosphere glow ring
 * - Star field background (200 dots)
 */
import { useRef, useMemo } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { OrbitControls } from '@react-three/drei'
import * as THREE from 'three'
import Panel from './Panel'
import { PANELS } from '../engine/layoutEngine'
import { useThreatState } from '../engine/threatState'

const R = 1.8 // Sphere radius
const NL = { lat: 52.37, lng: 4.89 }
const ARC_SEGS = 48

// ── Geo utilities ────────────────────────────────────────────────────────────

function llv(lat, lng, r = R) {
  const phi = (90 - lat) * (Math.PI / 180)
  const theta = (lng + 180) * (Math.PI / 180)
  return new THREE.Vector3(
    -r * Math.sin(phi) * Math.cos(theta),
    r * Math.cos(phi),
    r * Math.sin(phi) * Math.sin(theta),
  )
}

function arcPoints(sLat, sLng, eLat, eLng) {
  const s = llv(sLat, sLng)
  const e = llv(eLat, eLng)
  const mid = new THREE.Vector3().addVectors(s, e).multiplyScalar(0.5)
  mid.normalize().multiplyScalar(R + s.distanceTo(e) * 0.35)
  return new THREE.QuadraticBezierCurve3(s, mid, e).getPoints(ARC_SEGS)
}

// ── Continent coastlines (simplified, ~500 vertices total) ───────────────────

const CL = [
  // North America
  [72,-168,71,-156,70,-141,64,-140,60,-139,55,-130,49,-128,48,-124,42,-124,38,-123,34,-120,30,-118,23,-110,18,-105,16,-96,14,-92,9,-84,8,-79,25,-80,30,-81,35,-75,40,-74,42,-70,44,-63,47,-53,52,-56,55,-60,60,-64,58,-78,55,-85,49,-95,52,-95,58,-94,64,-97,70,-105,72,-120,72,-168],
  // South America
  [12,-72,10,-76,8,-79,4,-78,0,-80,-5,-81,-6,-77,-13,-76,-18,-71,-22,-70,-27,-71,-33,-71,-42,-65,-46,-68,-54,-70,-55,-67,-52,-68,-41,-73,-33,-72,-28,-49,-23,-41,-13,-39,-5,-35,-2,-50,2,-52,7,-58,10,-62,12,-72],
  // Europe
  [36,-6,38,-9,43,-9,44,-1,47,-2,48,5,51,4,52,5,54,9,55,8,57,10,58,12,63,11,64,14,68,16,70,20,71,28,70,32,67,41,62,43,60,30,57,24,54,20,50,14,48,17,44,12,41,15,38,24,36,0,36,-6],
  // Africa
  [37,10,36,0,36,-6,33,-8,28,-13,21,-17,15,-17,12,-16,5,-4,4,7,0,9,-4,12,-12,14,-16,12,-24,15,-28,16,-33,18,-35,20,-34,26,-30,31,-25,35,-15,41,-3,41,2,45,10,51,12,44,15,40,20,40,25,37,30,32,37,10],
  // Asia
  [42,28,40,44,38,49,25,57,12,52,8,77,1,104,-8,110,-8,115,2,110,7,100,10,99,20,106,22,114,30,122,35,129,38,140,42,133,46,143,50,140,53,142,55,137,59,143,62,163,65,177,69,180,70,170,67,140,58,138,53,142,45,138,34,127,22,114,18,108,22,97,28,97,35,78,37,71,42,53,42,28],
  // Australia
  [-12,130,-14,127,-22,114,-28,114,-32,116,-35,117,-35,137,-38,145,-38,148,-34,151,-28,153,-19,147,-13,136,-12,130],
  // Greenland
  [83,-38,82,-22,78,-18,76,-18,72,-22,60,-43,60,-48,64,-52,69,-54,72,-56,76,-68,80,-66,82,-50,83,-38],
  // Japan
  [31,131,33,131,35,134,37,137,39,140,42,141,43,145,45,142,42,143,40,140,37,137,34,135,31,131],
  // UK
  [50,-5,51,-3,52,1,53,0,54,-1,55,-2,57,-6,58,-5,58,-3,56,-3,55,-1,53,1,51,1,50,-5],
  // Indonesia
  [-6,106,-7,110,-8,114,-8,117,-7,120,-5,119,-3,116,-2,113,-5,107,-6,106],
]

function Coastlines({ color, opacity }) {
  const geos = useMemo(() =>
    CL.map(c => {
      const pts = []
      for (let i = 0; i < c.length; i += 2) pts.push(llv(c[i], c[i+1], R * 1.002))
      const a = new Float32Array(pts.length * 3)
      pts.forEach((p, i) => { a[i*3]=p.x; a[i*3+1]=p.y; a[i*3+2]=p.z })
      return { a, n: pts.length }
    })
  , [])

  return (
    <group>
      {geos.map((g, i) => (
        <line key={i}>
          <bufferGeometry>
            <bufferAttribute attach="attributes-position" count={g.n} array={g.a} itemSize={3} />
          </bufferGeometry>
          <lineBasicMaterial color={color} transparent opacity={opacity} />
        </line>
      ))}
    </group>
  )
}

// ── Star field ───────────────────────────────────────────────────────────────

function Stars() {
  const positions = useMemo(() => {
    const a = new Float32Array(200 * 3)
    for (let i = 0; i < 200; i++) {
      const r = 12 + Math.random() * 8
      const theta = Math.random() * Math.PI * 2
      const phi = Math.acos(2 * Math.random() - 1)
      a[i*3]   = r * Math.sin(phi) * Math.cos(theta)
      a[i*3+1] = r * Math.sin(phi) * Math.sin(theta)
      a[i*3+2] = r * Math.cos(phi)
    }
    return a
  }, [])

  return (
    <points>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" count={200} array={positions} itemSize={3} />
      </bufferGeometry>
      <pointsMaterial color="#ffffff" size={0.04} transparent opacity={0.5} sizeAttenuation />
    </points>
  )
}

// ── Globe core ───────────────────────────────────────────────────────────────

function Globe({ threatState }) {
  const groupRef = useRef()

  const color = threatState === 'CRITICAL' ? '#ff0040'
    : threatState === 'ACTIVE' ? '#00d4ff'
    : threatState === 'ELEVATED' ? '#ff8c00'
    : '#00d4ff'

  const coastOpacity = threatState === 'CRITICAL' ? 0.5 : threatState === 'ELEVATED' ? 0.4 : 0.3

  useFrame((_, delta) => {
    if (groupRef.current) groupRef.current.rotation.y += delta * 0.05
  })

  return (
    <group ref={groupRef}>
      {/* Wireframe sphere */}
      <mesh>
        <sphereGeometry args={[R, 36, 24]} />
        <meshBasicMaterial color={color} wireframe transparent opacity={0.06} />
      </mesh>

      {/* Inner volume */}
      <mesh>
        <sphereGeometry args={[R * 0.97, 16, 12]} />
        <meshBasicMaterial color={color} transparent opacity={0.015} />
      </mesh>

      {/* Atmosphere glow (backside rim) */}
      <mesh>
        <sphereGeometry args={[R * 1.12, 48, 48]} />
        <meshBasicMaterial color={color} transparent opacity={0.02} side={THREE.BackSide} />
      </mesh>

      {/* Equator */}
      <mesh rotation={[Math.PI/2, 0, 0]}>
        <ringGeometry args={[R*1.005, R*1.015, 64]} />
        <meshBasicMaterial color={color} transparent opacity={0.1} side={THREE.DoubleSide} />
      </mesh>

      {/* Latitude lines at 30° 60° */}
      {[30, 60, -30, -60].map(lat => {
        const cr = R * 1.003 * Math.cos(lat * Math.PI / 180)
        const y  = R * 1.003 * Math.sin(lat * Math.PI / 180)
        return (
          <mesh key={lat} position={[0, y, 0]} rotation={[Math.PI/2, 0, 0]}>
            <ringGeometry args={[cr - 0.003, cr, 48]} />
            <meshBasicMaterial color={color} transparent opacity={0.05} side={THREE.DoubleSide} />
          </mesh>
        )
      })}

      {/* Continents */}
      <Coastlines color={color} opacity={coastOpacity} />

      {/* NL home base — large pulsing cyan dot */}
      <HomeBase />
    </group>
  )
}

function HomeBase() {
  const ref = useRef()
  const pos = useMemo(() => llv(NL.lat, NL.lng, R * 1.01), [])

  useFrame(({ clock }) => {
    if (!ref.current) return
    const t = clock.elapsedTime
    ref.current.material.opacity = 0.6 + Math.sin(t * 3) * 0.4
    ref.current.scale.setScalar(0.8 + Math.sin(t * 3) * 0.3)
  })

  return (
    <mesh ref={ref} position={pos}>
      <sphereGeometry args={[0.06, 10, 10]} />
      <meshBasicMaterial color="#00d4ff" transparent opacity={0.8} />
    </mesh>
  )
}

// ── Attack visualization ─────────────────────────────────────────────────────

function Attacks({ events }) {
  const groupRef = useRef()

  const attacks = useMemo(() => {
    const seen = new Set()
    return (events || [])
      .filter(e => {
        if (!e.source_latitude || !e.source_longitude) return false
        const k = `${e.source_latitude.toFixed(0)},${e.source_longitude.toFixed(0)}`
        if (seen.has(k)) return false
        seen.add(k)
        return true
      })
      .slice(0, 20)
      .map(e => {
        const lat = e.source_latitude
        const lng = e.source_longitude
        const risk = e.risk_score ?? 0
        const dotPos = llv(lat, lng, R * 1.015)
        const pts = arcPoints(lat, lng, NL.lat, NL.lng)

        // Gradient colors: red → orange → cyan
        const positions = new Float32Array(pts.length * 3)
        const colors = new Float32Array(pts.length * 3)
        pts.forEach((p, i) => {
          positions[i*3] = p.x; positions[i*3+1] = p.y; positions[i*3+2] = p.z
          const t = i / (pts.length - 1)
          if (t < 0.4) {
            // Red
            colors[i*3] = 1; colors[i*3+1] = t * 0.5; colors[i*3+2] = 0.02
          } else if (t < 0.7) {
            // Orange
            const t2 = (t - 0.4) / 0.3
            colors[i*3] = 1; colors[i*3+1] = 0.2 + t2 * 0.35; colors[i*3+2] = t2 * 0.1
          } else {
            // Fade to cyan
            const t2 = (t - 0.7) / 0.3
            colors[i*3] = 1 - t2; colors[i*3+1] = 0.55 + t2 * 0.28; colors[i*3+2] = t2 * 0.8
          }
        })
        return { dotPos, positions, colors, count: pts.length, risk }
      })
  }, [events])

  // Pulse each dot individually
  useFrame(({ clock }) => {
    if (!groupRef.current) return
    let idx = 0
    groupRef.current.children.forEach(child => {
      if (child.type === 'Mesh') {
        const t = clock.elapsedTime * 4 + idx * 1.2
        child.material.opacity = 0.5 + Math.sin(t) * 0.5
        idx++
      }
    })
  })

  if (attacks.length === 0) return null

  return (
    <group ref={groupRef}>
      {attacks.map((a, i) => (
        <group key={i}>
          <mesh position={a.dotPos}>
            <sphereGeometry args={[0.04, 8, 8]} />
            <meshBasicMaterial color="#ff0040" transparent opacity={0.8} />
          </mesh>
          <line>
            <bufferGeometry>
              <bufferAttribute attach="attributes-position" count={a.count} array={a.positions} itemSize={3} />
              <bufferAttribute attach="attributes-color" count={a.count} array={a.colors} itemSize={3} />
            </bufferGeometry>
            <lineBasicMaterial vertexColors transparent opacity={0.5} />
          </line>
        </group>
      ))}
    </group>
  )
}

// ── Globe panel ──────────────────────────────────────────────────────────────

export default function GlobePanel() {
  const { current, events } = useThreatState()

  return (
    <Panel panelId={PANELS.GLOBE} title="THREAT MAP" icon="◉">
      <div style={{ width: '100%', height: '100%', minHeight: 180 }}>
        <Canvas
          camera={{ position: [0, 1.2, 4.5], fov: 45 }}
          style={{ background: 'transparent' }}
          gl={{ antialias: true, alpha: true }}
        >
          <ambientLight intensity={0.3} />
          <Stars />
          <Globe threatState={current} />
          <Attacks events={events} />
          <OrbitControls
            enableZoom={false}
            enablePan={false}
            autoRotate
            autoRotateSpeed={0.2}
            minPolarAngle={Math.PI / 5}
            maxPolarAngle={Math.PI * 4 / 5}
          />
        </Canvas>
      </div>
    </Panel>
  )
}
