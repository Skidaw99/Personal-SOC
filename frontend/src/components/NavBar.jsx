/**
 * NavBar — persistent top navigation across all screens.
 *
 * 48px glassmorphism bar, 7 tabs, alert badge,
 * threat level indicator, username, logout.
 */
import { useGlobalThreat } from '../hooks/useThreatState'

const TABS = [
  { key: 'soc', label: 'SOC' },
  { key: 'dashboard', label: 'DASHBOARD' },
  { key: 'accounts', label: 'ACCOUNTS' },
  { key: 'alerts', label: 'ALERTS' },
  { key: 'intel', label: 'INTEL' },
  { key: 'actors', label: 'ACTORS' },
  { key: 'copilot', label: 'COPILOT' },
]

export default function NavBar({ screen, setScreen, onLogout }) {
  const { threatLevel, threatColor, openAlertCount, criticalAlertCount } = useGlobalThreat()
  const username = localStorage.getItem('sfd_user') || 'operator'

  return (
    <nav className="nav-bar">
      {/* Logo */}
      <div className="nav-logo">
        <span className="nav-logo-icon">&#9741;</span>
        <span className="nav-logo-text">SOC</span>
      </div>

      {/* Tabs */}
      <div className="nav-tabs">
        {TABS.map(tab => (
          <button
            key={tab.key}
            className={`nav-tab ${screen === tab.key ? 'nav-tab-active' : ''}`}
            onClick={() => setScreen(tab.key)}
          >
            {tab.label}
            {tab.key === 'alerts' && openAlertCount > 0 && (
              <span className={`nav-badge ${criticalAlertCount > 0 ? 'nav-badge-critical' : ''}`}>
                {openAlertCount}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Right side */}
      <div className="nav-right">
        <div className="nav-threat-indicator">
          <span className="nav-threat-dot" style={{
            background: threatColor,
            boxShadow: `0 0 8px ${threatColor}`,
            animation: threatLevel === 'CRITICAL' ? 'pulse-dot 1s ease infinite' : 'none',
          }} />
          <span style={{ color: threatColor }}>{threatLevel}</span>
        </div>
        <span className="nav-username">{username}</span>
        <button className="nav-logout" onClick={onLogout}>LOGOUT</button>
      </div>
    </nav>
  )
}
