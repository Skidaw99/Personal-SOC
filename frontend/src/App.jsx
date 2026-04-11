/**
 * App Shell — Auth gate + 7-screen router.
 *
 * Unauthenticated → LoginScreen
 * Authenticated → NavBar + CriticalBanner + active screen
 */
import { useState, useEffect } from 'react'
import { api } from './api'
import { GlobalThreatProvider } from './hooks/useThreatState'
import LoginScreen from './screens/LoginScreen'
import NavBar from './components/NavBar'
import CriticalBanner from './components/CriticalBanner'
import SOCScreen from './screens/SOCScreen'
import DashboardScreen from './screens/DashboardScreen'
import AccountsScreen from './screens/AccountsScreen'
import AlertsScreen from './screens/AlertsScreen'
import IntelScreen from './screens/IntelScreen'
import ActorsScreen from './screens/ActorsScreen'
import CopilotScreen from './screens/CopilotScreen'

export default function App() {
  const [authed, setAuthed] = useState(false)
  const [checking, setChecking] = useState(true)
  const [screen, setScreen] = useState('soc')

  // Check existing credentials on mount
  useEffect(() => {
    const user = localStorage.getItem('sfd_user')
    if (user) {
      api.checkAuth()
        .then(() => setAuthed(true))
        .catch(() => setAuthed(false))
        .finally(() => setChecking(false))
    } else {
      setChecking(false)
    }
  }, [])

  function handleLogin() {
    setAuthed(true)
    setScreen('soc')
  }

  function handleLogout() {
    localStorage.removeItem('sfd_user')
    localStorage.removeItem('sfd_pass')
    setAuthed(false)
    setScreen('soc')
  }

  // Navigate to alerts with optional filter
  function navigateToAlerts(filter) {
    setScreen('alerts')
  }

  if (checking) {
    return (
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        height: '100vh', background: 'var(--bg-void)',
        fontFamily: 'var(--font-display)', fontSize: 14,
        letterSpacing: '3px', color: 'var(--cyan)',
      }}>
        INITIALIZING...
      </div>
    )
  }

  if (!authed) {
    return <LoginScreen onLogin={handleLogin} />
  }

  return (
    <GlobalThreatProvider>
      <NavBar screen={screen} setScreen={setScreen} onLogout={handleLogout} />
      <CriticalBanner />
      <div className="screen-container">
        {screen === 'soc' && <SOCScreen />}
        {screen === 'dashboard' && <DashboardScreen onNavigate={setScreen} />}
        {screen === 'accounts' && <AccountsScreen />}
        {screen === 'alerts' && <AlertsScreen />}
        {screen === 'intel' && <IntelScreen />}
        {screen === 'actors' && <ActorsScreen />}
        {screen === 'copilot' && <CopilotScreen />}
      </div>
    </GlobalThreatProvider>
  )
}
