const BASE = '/api'

function getHeaders() {
  const user = localStorage.getItem('sfd_user') || ''
  const pass = localStorage.getItem('sfd_pass') || ''
  const creds = btoa(`${user}:${pass}`)
  return {
    'Content-Type': 'application/json',
    Authorization: `Basic ${creds}`,
  }
}

function getAuthToken() {
  const user = localStorage.getItem('sfd_user') || ''
  const pass = localStorage.getItem('sfd_pass') || ''
  return btoa(`${user}:${pass}`)
}

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: { ...getHeaders(), ...(options.headers || {}) },
  })
  if (res.status === 401) {
    localStorage.removeItem('sfd_user')
    localStorage.removeItem('sfd_pass')
    window.location.reload()
    return
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Request failed')
  }
  if (res.status === 204) return null
  return res.json()
}

async function socRequest(path, options = {}) {
  const res = await fetch(`/api/soc${path}`, {
    ...options,
    headers: { ...getHeaders(), ...(options.headers || {}) },
  })
  if (res.status === 401) {
    localStorage.removeItem('sfd_user')
    localStorage.removeItem('sfd_pass')
    window.location.reload()
    return
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Request failed')
  }
  if (res.status === 204) return null
  return res.json()
}

export const api = {
  // Auth
  checkAuth:       ()           => request('/stats/dashboard'),

  // Stats
  getSummary:      ()           => request('/stats/summary'),
  getDashboard:    ()           => request('/stats/dashboard'),

  // Accounts
  getAccounts:     ()           => request('/accounts/'),
  addAccount:      (body)       => request('/accounts/', { method: 'POST', body: JSON.stringify(body) }),
  updateAccount:   (id, body)   => request(`/accounts/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteAccount:   (id)         => request(`/accounts/${id}`, { method: 'DELETE' }),

  // Alerts
  getAlerts:       (params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
    return request(`/alerts/?${qs}`)
  },
  getAlert:        (id)         => request(`/alerts/${id}`),
  updateAlert:     (id, body)   => request(`/alerts/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  ackAlert:        (id, notes)  => request(`/alerts/${id}/acknowledge`, { method: 'POST', body: JSON.stringify({ notes: notes || null }) }),
  resolveAlert:    (id, body)   => request(`/alerts/${id}/resolve`, { method: 'POST', body: JSON.stringify(body || { status: 'resolved' }) }),

  // Events
  getEvents:       (params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
    return request(`/events/?${qs}`)
  },

  // SOC Intel
  lookupIP:        (ip)         => socRequest('/intel/lookup', { method: 'POST', body: JSON.stringify({ ip }) }),
  getActors:       ()           => socRequest('/actors/'),
  getActor:        (id)         => socRequest(`/actors/${id}`),

  // SOC AI
  aiChat:          (message, riskScore, context) => socRequest('/ai/chat', {
    method: 'POST',
    body: JSON.stringify({ message, risk_score: riskScore || 0, context: context || null }),
  }),
  aiAnalyze:       (data)       => socRequest('/ai/analyze', { method: 'POST', body: JSON.stringify(data) }),
  generateFBIBrief:(data)       => socRequest('/ai/fbi-brief', { method: 'POST', body: JSON.stringify(data) }),
}

export { getAuthToken }
