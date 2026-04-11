/**
 * Globe Panel — Three.js earth with continent outlines + live attack arcs.
 *
 * Features:
 * - Wireframe sphere base with grid dots
 * - Continent coastline outlines (embedded coordinates)
 * - Netherlands home base — bright cyan pulsing dot
 * - Attacker locations — red pulsing dots
 * - Curved attack arcs from source IP geo → NL
 * - Color intensity adapts to threat state
 */
import { useRef, useMemo, useCallback } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { OrbitControls } from '@react-three/drei'
import * as THREE from 'three'
import Panel from './Panel'
import { PANELS } from '../engine/layoutEngine'
import { useThreatState } from '../engine/threatState'

// ── Constants ────────────────────────────────────────────────────────────────

const SPHERE_RADIUS = 1.8
const NL_LAT = 52.37
const NL_LNG = 4.89
const ARC_SEGMENTS = 48
const ARC_HEIGHT_SCALE = 0.35

// ── Geo utilities ────────────────────────────────────────────────────────────

function latLngToVec3(lat, lng, radius = SPHERE_RADIUS) {
  const phi = (90 - lat) * (Math.PI / 180)
  const theta = (lng + 180) * (Math.PI / 180)
  return new THREE.Vector3(
    -radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta),
  )
}

function createArcPoints(startLat, startLng, endLat, endLng, segments = ARC_SEGMENTS) {
  const start = latLngToVec3(startLat, startLng)
  const end = latLngToVec3(endLat, endLng)
  const dist = start.distanceTo(end)
  const mid = new THREE.Vector3().addVectors(start, end).multiplyScalar(0.5)
  const height = dist * ARC_HEIGHT_SCALE

  // Push midpoint outward from sphere center
  mid.normalize().multiplyScalar(SPHERE_RADIUS + height)

  const curve = new THREE.QuadraticBezierCurve3(start, mid, end)
  return curve.getPoints(segments)
}

// ── Simplified continent coastlines ──────────────────────────────────────────
// Each sub-array is [lat, lng, lat, lng, ...] pairs forming a closed polyline.

const COASTLINES = [
  // North America
  [72,-168,71,-156,70,-141,64,-140,60,-139,55,-130,49,-128,48,-124,
   38,-123,34,-120,30,-118,23,-110,16,-96,14,-92,9,-84,8,-79,
   25,-80,30,-81,35,-75,40,-74,42,-70,44,-63,47,-53,52,-56,
   55,-60,60,-64,58,-78,55,-85,49,-95,52,-95,58,-94,64,-97,
   70,-105,72,-120,72,-168],
  // South America
  [12,-72,10,-76,8,-79,4,-78,0,-80,-5,-81,-6,-77,-13,-76,
   -18,-71,-27,-71,-33,-71,-42,-65,-46,-68,-54,-70,-55,-67,
   -52,-68,-41,-73,-33,-72,-28,-49,-23,-41,-13,-39,-5,-35,
   -2,-50,2,-52,7,-58,10,-62,12,-72],
  // Europe
  [36,-6,38,-9,43,-9,44,-1,47,-2,48,5,51,4,52,5,54,9,
   55,8,57,10,58,12,63,11,64,14,68,16,70,20,71,28,
   70,32,67,41,62,43,60,30,57,24,54,20,50,14,48,17,
   44,12,41,15,38,24,36,0,36,-6],
  // Africa
  [37,10,36,0,36,-6,33,-8,28,-13,21,-17,15,-17,12,-16,
   5,-4,4,7,0,9,-4,12,-12,14,-16,12,-24,15,-28,16,
   -33,18,-35,20,-34,26,-30,31,-25,35,-15,41,-3,41,
   2,45,10,51,12,44,15,40,20,40,25,37,30,32,37,10],
  // Asia
  [42,28,40,44,38,49,25,57,12,52,8,77,1,104,-8,110,
   -8,115,2,110,7,100,10,99,20,106,22,114,30,122,
   35,129,38,140,42,133,46,143,50,140,53,142,55,137,
   59,143,62,163,65,177,69,180,70,170,67,140,58,138,
   53,142,45,138,34,127,22,114,18,108,22,97,28,97,
   35,78,37,71,42,53,42,28],
  // Australia
  [-12,130,-14,127,-22,114,-28,114,-32,116,-35,117,-35,137,
   -38,145,-38,148,-34,151,-28,153,-19,147,-13,136,-12,130],
  // Greenland
  [83,-38,82,-22,78,-18,76,-18,72,-22,60,-43,60,-48,
   64,-52,69,-54,72,-56,76,-68,80,-66,82,-50,83,-38],
  // Japan
  [31,131,33,131,34,132,35,134,36,136,37,137,39,140,40,140,
   42,141,43,145,45,142,44,143,42,143,40,140,38,139,35,137,
   34,135,33,133,31,131],
  // UK + Ireland
  [50,-5,51,-3,52,1,53,0,54,-1,55,-2,57,-6,58,-5,58,-3,
   56,-3,55,-1,53,1,51,1,50,-5],
  [52,-10,53,-10,54,-8,53,-6,52,-6,51,-9,52,-10],
];

// ── Coastline geometry (runs once) ───────────────────────────────────────────

function CoastlineOutlines({ color, opacity }) {
  const geometries = useMemo(() => {
    return COASTLINES.map(coords => {
      const points = []
      for (let i = 0; i < coords.length; i += 2) {
        points.push(latLngToVec3(coords[i], coords[i + 1], SPHERE_RADIUS * 1.002))
      }
      const arr = new Float32Array(points.length * 3)
      points.forEach((p, i) => { arr[i * 3] = p.x; arr[i * 3 + 1] = p.y; arr[i * 3 + 2] = p.z })
      return { array: arr, count: points.length }
    })
  }, [])

  return (
    <group>
      {geometries.map((geo, i) => (
        <line key={i}>
          <bufferGeometry>
            <bufferAttribute
              attach="attributes-position"
              count={geo.count}
              array={geo.array}
              itemSize={3}
            />
          </bufferGeometry>
          <lineBasicMaterial color={color} transparent opacity={opacity} />
        </line>
      ))}
    </group>
  )
}

// ── Wireframe globe ──────────────────────────────────────────────────────────

function WireframeGlobe({ threatState }) {
  const meshRef = useRef()

  const color = threatState === 'CRITICAL' ? '#ff0040'
    : threatState === 'ACTIVE' ? '#00d4ff'
    : threatState === 'ELEVATED' ? '#ffaa00'
    : '#00d4ff'

  const coastlineOpacity = threatState === 'CRITICAL' ? 0.5 : 0.3

  useFrame((_, delta) => {
    if (meshRef.current) {
      meshRef.current.rotation.y += delta * 0.06
    }
  })

  return (
    <group ref={meshRef}>
      {/* Wireframe sphere */}
      <mesh>
        <sphereGeometry args={[SPHERE_RADIUS, 36, 24]} />
        <meshBasicMaterial color={color} wireframe transparent opacity={0.08} />
      </mesh>

      {/* Inner glow */}
      <mesh>
        <sphereGeometry args={[SPHERE_RADIUS * 0.98, 16, 12]} />
        <meshBasicMaterial color={color} transparent opacity={0.02} />
      </mesh>

      {/* Equator ring */}
      <mesh rotation={[Math.PI / 2, 0, 0]}>
        <ringGeometry args={[SPHERE_RADIUS * 1.01, SPHERE_RADIUS * 1.02, 64]} />
        <meshBasicMaterial color={color} transparent opacity={0.12} side={THREE.DoubleSide} />
      </mesh>

      {/* Latitude lines at 30 and 60 degrees */}
      {[30, 60, -30, -60].map(lat => {
        const r = SPHERE_RADIUS * 1.005 * Math.cos(lat * Math.PI / 180)
        const y = SPHERE_RADIUS * 1.005 * Math.sin(lat * Math.PI / 180)
        return (
          <mesh key={lat} position={[0, y, 0]} rotation={[Math.PI / 2, 0, 0]}>
            <ringGeometry args={[r - 0.003, r, 48]} />
            <meshBasicMaterial color={color} transparent opacity={0.06} side={THREE.DoubleSide} />
          </mesh>
        )
      })}

      {/* Continent outlines */}
      <CoastlineOutlines color={color} opacity={coastlineOpacity} />

      {/* NL home base — bright pulsing dot */}
      <HomeBase />
    </group>
  )
}

// ── Netherlands home base ────────────────────────────────────────────────────

function HomeBase() {
  const ref = useRef()
  const pos = useMemo(() => latLngToVec3(NL_LAT, NL_LNG, SPHERE_RADIUS * 1.01), [])

  useFrame(({ clock }) => {
    if (ref.current) {
      const pulse = 0.6 + Math.sin(clock.elapsedTime * 3) * 0.4
      ref.current.material.opacity = pulse
      const s = 0.8 + Math.sin(clock.elapsedTime * 3) * 0.3
      ref.current.scale.setScalar(s)
    }
  })

  return (
    <mesh ref={ref} position={pos}>
      <sphereGeometry args={[0.04, 8, 8]} />
      <meshBasicMaterial color="#00d4ff" transparent opacity={0.8} />
    </mesh>
  )
}

// ── Attack dots + arcs ───────────────────────────────────────────────────────

function AttackVisualization({ events }) {
  const groupRef = useRef()

  const attacks = useMemo(() => {
    const seen = new Set()
    return (events || [])
      .filter(e => {
        if (!e.source_latitude || !e.source_longitude) return false
        const key = `${e.source_latitude.toFixed(1)},${e.source_longitude.toFixed(1)}`
        if (seen.has(key)) return false
        seen.add(key)
        return true
      })
      .slice(0, 20)
      .map(e => {
        const lat = e.source_latitude
        const lng = e.source_longitude
        const risk = e.risk_score ?? 0
        const color = risk >= 90 ? '#ff0040' : risk >= 70 ? '#ff8c00' : '#ffaa00'
        const dotPos = latLngToVec3(lat, lng, SPHERE_RADIUS * 1.015)
        const arcPoints = createArcPoints(lat, lng, NL_LAT, NL_LNG)
        const arcArray = new Float32Array(arcPoints.length * 3)
        arcPoints.forEach((p, i) => {
          arcArray[i * 3] = p.x
          arcArray[i * 3 + 1] = p.y
          arcArray[i * 3 + 2] = p.z
        })
        return { dotPos, color, arcArray, arcCount: arcPoints.length, risk }
      })
  }, [events])

  // Animate attack dots pulse
  useFrame(({ clock }) => {
    if (!groupRef.current) return
    groupRef.current.children.forEach((child, i) => {
      if (child.type === 'Mesh') {
        const pulse = 0.4 + Math.sin(clock.elapsedTime * 4 + i) * 0.4
        child.material.opacity = pulse
      }
    })
  })

  if (attacks.length === 0) return null

  return (
    <group ref={groupRef}>
      {attacks.map((atk, i) => (
        <group key={i}>
          {/* Attack source dot */}
          <mesh position={atk.dotPos}>
            <sphereGeometry args={[0.03, 6, 6]} />
            <meshBasicMaterial color={atk.color} transparent opacity={0.8} />
          </mesh>

          {/* Attack arc */}
          <line>
            <bufferGeometry>
              <bufferAttribute
                attach="attributes-position"
                count={atk.arcCount}
                array={atk.arcArray}
                itemSize={3}
              />
            </bufferGeometry>
            <lineBasicMaterial
              color={atk.color}
              transparent
              opacity={atk.risk >= 90 ? 0.6 : 0.35}
            />
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
      <div style={{ width: '100%', height: '100%', minHeight: 200 }}>
        <Canvas
          camera={{ position: [0, 1.2, 4.5], fov: 45 }}
          style={{ background: 'transparent' }}
          gl={{ antialias: true, alpha: true }}
        >
          <ambientLight intensity={0.4} />
          <WireframeGlobe threatState={current} />
          <AttackVisualization events={events} />
          <OrbitControls
            enableZoom={false}
            enablePan={false}
            autoRotate
            autoRotateSpeed={0.3}
            minPolarAngle={Math.PI / 5}
            maxPolarAngle={Math.PI * 4 / 5}
          />
        </Canvas>
      </div>
    </Panel>
  )
}
