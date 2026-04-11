/**
 * Critical Banner — persistent across ALL screens.
 *
 * Shows when global threat level is CRITICAL.
 * Red pulsing banner with threat details.
 */
import { useGlobalThreat } from '../hooks/useThreatState'

export default function CriticalBanner() {
  const { isCritical, criticalAlert } = useGlobalThreat()

  if (!isCritical) return null

  const title = criticalAlert?.title || 'CRITICAL THREAT DETECTED'
  const risk = criticalAlert?.risk_score ?? 0
  const category = (criticalAlert?.category || '').replace(/_/g, ' ').toUpperCase()

  return (
    <div className="critical-banner-global">
      <div className="critical-banner-global-inner">
        <span className="critical-banner-icon">&#9888;</span>
        <span className="critical-banner-text">CRITICAL</span>
        <span className="critical-banner-sep">|</span>
        <span className="critical-banner-detail">{category || title}</span>
        {risk > 0 && (
          <>
            <span className="critical-banner-sep">|</span>
            <span className="critical-banner-risk">RISK {risk.toFixed(0)}</span>
          </>
        )}
      </div>
    </div>
  )
}
