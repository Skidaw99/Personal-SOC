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

export const api = {
  getSummary:    ()           => request('/stats/summary'),
  getAlerts:     (params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v))
    return request(`/alerts/?${qs}`)
  },
  updateAlert:   (id, body)   => request(`/alerts/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  getAccounts:   ()           => request('/accounts/'),
  addAccount:    (body)       => request('/accounts/', { method: 'POST', body: JSON.stringify(body) }),
  deleteAccount: (id)         => request(`/accounts/${id}`, { method: 'DELETE' }),
  updateAccount: (id, body)   => request(`/accounts/${id}/status`, { method: 'PATCH', body: JSON.stringify(body) }),
  checkAuth:     ()           => request('/stats/summary'),
}
