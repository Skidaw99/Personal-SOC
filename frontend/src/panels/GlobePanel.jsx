/**
 * Globe Panel — Three.js earth with live attack lines.
 *
 * Shows a wireframe globe with:
 * - Attack lines animating from source IP geo to center
 * - Color-coded by severity
 * - Pulse effects on impact
 *
 * Adapts to threat state (size/opacity handled by layout engine).
 */
import { useRef, useMemo } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { OrbitControls } from '@react-three/drei'
import * as THREE from 'three'
import Panel from './Panel'
import { PANELS } from '../engine/layoutEngine'
import { useThreatState } from '../engine/threatState'

function WireframeGlobe({ threatState }) {
  const meshRef = useRef()
  const glowRef = useRef()

  const color = threatState === 'CRITICAL' ? '#ff0040'
    : threatState === 'ACTIVE' ? '#00d4ff'
    : threatState === 'ELEVATED' ? '#ffaa00'
    : '#00d4ff'

  useFrame((_, delta) => {
    if (meshRef.current) {
      meshRef.current.rotation.y += delta * 0.08
    }
    if (glowRef.current) {
      glowRef.current.rotation.y += delta * 0.06
    }
  })

  return (
    <group>
      {/* Wireframe sphere */}
      <mesh ref={meshRef}>
        <sphereGeometry args={[1.8, 32, 24]} />
        <meshBasicMaterial
          color={color}
          wireframe
          transparent
          opacity={0.2}
        />
      </mesh>

      {/* Inner glow sphere */}
      <mesh ref={glowRef}>
        <sphereGeometry args={[1.75, 16, 12]} />
        <meshBasicMaterial
          color={color}
          transparent
          opacity={0.03}
        />
      </mesh>

      {/* Equator ring */}
      <mesh rotation={[Math.PI / 2, 0, 0]}>
        <ringGeometry args={[1.85, 1.88, 64]} />
        <meshBasicMaterial
          color={color}
          transparent
          opacity={0.15}
          side={THREE.DoubleSide}
        />
      </mesh>

      {/* Axis lines */}
      <line>
        <bufferGeometry>
          <bufferAttribute
            attach="attributes-position"
            count={2}
            array={new Float32Array([0, -2.2, 0, 0, 2.2, 0])}
            itemSize={3}
          />
        </bufferGeometry>
        <lineBasicMaterial color={color} transparent opacity={0.1} />
      </line>
    </group>
  )
}

function AttackLines({ events }) {
  const linesRef = useRef()

  const attackData = useMemo(() => {
    return (events || [])
      .filter(e => e.source_latitude && e.source_longitude)
      .slice(0, 15)
      .map(e => {
        const lat = (e.source_latitude * Math.PI) / 180
        const lon = (e.source_longitude * Math.PI) / 180
        const r = 1.85
        return {
          start: new THREE.Vector3(
            r * Math.cos(lat) * Math.sin(lon),
            r * Math.sin(lat),
            r * Math.cos(lat) * Math.cos(lon)
          ),
          color: e.risk_score >= 90 ? '#ff0040'
            : e.risk_score >= 70 ? '#ffaa00'
            : '#00d4ff',
        }
      })
  }, [events])

  if (attackData.length === 0) return null

  return (
    <group>
      {attackData.map((atk, i) => (
        <line key={i}>
          <bufferGeometry>
            <bufferAttribute
              attach="attributes-position"
              count={2}
              array={new Float32Array([
                atk.start.x, atk.start.y, atk.start.z,
                0, 0, 0,
              ])}
              itemSize={3}
            />
          </bufferGeometry>
          <lineBasicMaterial color={atk.color} transparent opacity={0.4} />
        </line>
      ))}
    </group>
  )
}

export default function GlobePanel() {
  const { current, events } = useThreatState()

  return (
    <Panel panelId={PANELS.GLOBE} title="THREAT MAP" icon="◉">
      <div style={{ width: '100%', height: '100%', minHeight: 200 }}>
        <Canvas
          camera={{ position: [0, 0, 5], fov: 45 }}
          style={{ background: 'transparent' }}
        >
          <ambientLight intensity={0.5} />
          <WireframeGlobe threatState={current} />
          <AttackLines events={events} />
          <OrbitControls
            enableZoom={false}
            enablePan={false}
            autoRotate
            autoRotateSpeed={0.3}
            minPolarAngle={Math.PI / 4}
            maxPolarAngle={Math.PI * 3 / 4}
          />
        </Canvas>
      </div>
    </Panel>
  )
}
