/**
 * Adaptive Layout Engine — positions floating panels based on threat state.
 *
 * Each panel has a layout config per threat state:
 *   { x, y, w, h, opacity, zIndex, priority }
 *
 * Values are in viewport percentages (vw/vh).
 * On state change, panels animate to their new positions via CSS transforms.
 *
 * Priority determines:
 *   - z-index (higher = in front)
 *   - opacity (higher = more visible)
 *   - scale when space is tight
 */
import { useMemo } from 'react'
import { useThreatState, THREAT_STATES } from './threatState'

// ── Panel IDs ───────────────────────────────────────────────────────────────

export const PANELS = {
  GLOBE:    'globe',
  FEED:     'feed',
  ACTOR:    'actor',
  INTEL:    'intel',
  COPILOT:  'copilot',
  STATS:    'stats',
}

// ── Layout definitions per state ────────────────────────────────────────────
// All values in viewport % { x, y, w, h } + opacity (0-1) + zIndex

const LAYOUTS = {

  // ── CALM: globe dominant, stats around, everything breathes ───────────
  [THREAT_STATES.CALM]: {
    [PANELS.GLOBE]:    { x: 15, y: 5,  w: 70, h: 65, opacity: 1,    zIndex: 1  },
    [PANELS.FEED]:     { x: 1,  y: 5,  w: 13, h: 55, opacity: 0.6,  zIndex: 2  },
    [PANELS.ACTOR]:    { x: 1,  y: 62, w: 20, h: 36, opacity: 0.4,  zIndex: 2  },
    [PANELS.INTEL]:    { x: 86, y: 5,  w: 13, h: 55, opacity: 0.5,  zIndex: 2  },
    [PANELS.COPILOT]:  { x: 72, y: 72, w: 27, h: 26, opacity: 0.7,  zIndex: 5  },
    [PANELS.STATS]:    { x: 22, y: 72, w: 20, h: 26, opacity: 0.4,  zIndex: 2  },
  },

  // ── ELEVATED: feeds come forward, globe shrinks, actor cards appear ───
  [THREAT_STATES.ELEVATED]: {
    [PANELS.GLOBE]:    { x: 25, y: 5,  w: 50, h: 50, opacity: 0.8,  zIndex: 1  },
    [PANELS.FEED]:     { x: 1,  y: 3,  w: 23, h: 65, opacity: 1,    zIndex: 4  },
    [PANELS.ACTOR]:    { x: 1,  y: 70, w: 30, h: 28, opacity: 0.9,  zIndex: 3  },
    [PANELS.INTEL]:    { x: 76, y: 3,  w: 23, h: 50, opacity: 0.9,  zIndex: 3  },
    [PANELS.COPILOT]:  { x: 70, y: 72, w: 29, h: 26, opacity: 0.8,  zIndex: 5  },
    [PANELS.STATS]:    { x: 32, y: 70, w: 20, h: 28, opacity: 0.5,  zIndex: 2  },
  },

  // ── ACTIVE: incident takes 60%, rest dimmed ───────────────────────────
  [THREAT_STATES.ACTIVE]: {
    [PANELS.GLOBE]:    { x: 1,  y: 1,  w: 28, h: 40, opacity: 0.5,  zIndex: 1  },
    [PANELS.FEED]:     { x: 30, y: 1,  w: 40, h: 60, opacity: 1,    zIndex: 4  },
    [PANELS.ACTOR]:    { x: 71, y: 1,  w: 28, h: 40, opacity: 1,    zIndex: 4  },
    [PANELS.INTEL]:    { x: 71, y: 42, w: 28, h: 30, opacity: 0.9,  zIndex: 3  },
    [PANELS.COPILOT]:  { x: 55, y: 62, w: 44, h: 36, opacity: 1,    zIndex: 5  },
    [PANELS.STATS]:    { x: 1,  y: 42, w: 28, h: 30, opacity: 0.5,  zIndex: 2  },
  },

  // ── CRITICAL: full takeover, only incident + copilot ──────────────────
  [THREAT_STATES.CRITICAL]: {
    [PANELS.GLOBE]:    { x: 0,  y: 0,  w: 30, h: 35, opacity: 0.2,  zIndex: 1  },
    [PANELS.FEED]:     { x: 1,  y: 1,  w: 58, h: 65, opacity: 1,    zIndex: 4  },
    [PANELS.ACTOR]:    { x: 60, y: 1,  w: 39, h: 40, opacity: 1,    zIndex: 4  },
    [PANELS.INTEL]:    { x: 60, y: 42, w: 39, h: 24, opacity: 0.8,  zIndex: 3  },
    [PANELS.COPILOT]:  { x: 40, y: 67, w: 59, h: 31, opacity: 1,    zIndex: 6  },
    [PANELS.STATS]:    { x: 1,  y: 67, w: 38, h: 31, opacity: 0.7,  zIndex: 3  },
  },
}

// ── Hook: get layout for a specific panel ───────────────────────────────────

export function usePanelLayout(panelId) {
  const { current } = useThreatState()

  return useMemo(() => {
    const layout = LAYOUTS[current]?.[panelId]
    if (!layout) return null

    return {
      ...layout,
      style: {
        left:      `${layout.x}vw`,
        top:       `${layout.y}vh`,
        width:     `${layout.w}vw`,
        height:    `${layout.h}vh`,
        opacity:   layout.opacity,
        zIndex:    layout.zIndex,
      },
    }
  }, [current, panelId])
}

// ── Hook: get all panel layouts for current state ───────────────────────────

export function useAllPanelLayouts() {
  const { current } = useThreatState()

  return useMemo(() => {
    const stateLayouts = LAYOUTS[current]
    if (!stateLayouts) return {}

    const result = {}
    for (const [panelId, layout] of Object.entries(stateLayouts)) {
      result[panelId] = {
        ...layout,
        style: {
          left:    `${layout.x}vw`,
          top:     `${layout.y}vh`,
          width:   `${layout.w}vw`,
          height:  `${layout.h}vh`,
          opacity: layout.opacity,
          zIndex:  layout.zIndex,
        },
      }
    }
    return result
  }, [current])
}
