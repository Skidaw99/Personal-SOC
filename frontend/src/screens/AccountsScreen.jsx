/**
 * Accounts Screen — social account management.
 *
 * CRUD table, add form with platform dropdown,
 * edit/delete, status badges, per-platform OAuth help.
 */
import { useState, useEffect } from 'react'
import { api } from '../api'

const PLATFORMS = ['facebook', 'instagram', 'twitter', 'linkedin', 'tiktok', 'youtube']

const STATUS_COLORS = {
  active: 'var(--green)',
  monitoring: 'var(--cyan)',
  suspended: 'var(--amber)',
  compromised: 'var(--red)',
}

const TOKEN_HELP = {
  facebook: 'Get token via: developers.facebook.com/tools/explorer — Select your app → Generate Access Token — Required permissions: email, public_profile',
  instagram: 'Get token via: developers.facebook.com/tools/explorer — Select your app → Generate Access Token — Required permissions: instagram_basic',
  twitter: 'Token is your Access Token from: developer.twitter.com → Your App → Keys and Tokens',
  youtube: 'Get token via: developers.google.com/oauthplayground — Scope: youtube.readonly — Use your Google Client ID + Secret',
  linkedin: 'Currently limited API access — visit developer.linkedin.com for details',
  tiktok: 'Currently limited API access — visit developers.tiktok.com for details',
}

const EMPTY_FORM = {
  platform: 'twitter',
  username: '',
  platform_user_id: '',
  display_name: '',
  access_token: '',
}

export default function AccountsScreen() {
  const [accounts, setAccounts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [showAdd, setShowAdd] = useState(false)
  const [form, setForm] = useState({ ...EMPTY_FORM })
  const [saving, setSaving] = useState(false)
  const [editId, setEditId] = useState(null)
  const [editForm, setEditForm] = useState({})
  const [showHelp, setShowHelp] = useState(false)

  async function fetchAccounts() {
    try {
      const data = await api.getAccounts()
      setAccounts(data || [])
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchAccounts() }, [])

  async function handleAdd(e) {
    e.preventDefault()
    if (!form.username.trim() || !form.platform_user_id.trim() || !form.access_token.trim()) return
    setSaving(true)
    try {
      await api.addAccount({
        platform: form.platform,
        username: form.username.trim(),
        platform_user_id: form.platform_user_id.trim(),
        display_name: form.display_name.trim() || null,
        access_token: form.access_token.trim(),
      })
      setForm({ ...EMPTY_FORM })
      setShowAdd(false)
      await fetchAccounts()
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete(id) {
    if (!window.confirm('Delete this account? This cannot be undone.')) return
    try {
      await api.deleteAccount(id)
      await fetchAccounts()
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleEdit(id) {
    setSaving(true)
    try {
      await api.updateAccount(id, editForm)
      setEditId(null)
      await fetchAccounts()
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  function startEdit(acc) {
    setEditId(acc.id)
    setEditForm({
      username: acc.username,
      display_name: acc.display_name || '',
      status: acc.status,
    })
  }

  if (loading) {
    return <div className="screen screen-center"><span className="loading-text">LOADING ACCOUNTS...</span></div>
  }

  return (
    <div className="screen">
      <div className="screen-header">
        <h2 className="screen-title">ACCOUNT MANAGEMENT</h2>
        <button className="btn btn-cyan" onClick={() => setShowAdd(!showAdd)}>
          {showAdd ? 'CANCEL' : '+ ADD ACCOUNT'}
        </button>
      </div>

      {error && <div className="error-card" style={{ marginBottom: 16 }}><span className="error-text">{error}</span></div>}

      {/* Add form */}
      {showAdd && (
        <form className="add-form" onSubmit={handleAdd}>
          <div className="form-row">
            <div className="form-group">
              <label className="form-label">PLATFORM</label>
              <select
                className="form-input form-select"
                value={form.platform}
                onChange={e => setForm({ ...form, platform: e.target.value })}
              >
                {PLATFORMS.map(p => <option key={p} value={p}>{p.toUpperCase()}</option>)}
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">USERNAME</label>
              <input className="form-input" value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} />
            </div>
            <div className="form-group">
              <label className="form-label">PLATFORM USER ID</label>
              <input className="form-input" value={form.platform_user_id} onChange={e => setForm({ ...form, platform_user_id: e.target.value })} />
            </div>
          </div>
          <div className="form-row">
            <div className="form-group">
              <label className="form-label">DISPLAY NAME (optional)</label>
              <input className="form-input" value={form.display_name} onChange={e => setForm({ ...form, display_name: e.target.value })} />
            </div>
            <div className="form-group">
              <label className="form-label">
                ACCESS TOKEN
                <button type="button" className="token-help-btn" onClick={() => setShowHelp(!showHelp)}>?</button>
              </label>
              <input className="form-input" type="password" value={form.access_token} onChange={e => setForm({ ...form, access_token: e.target.value })} />
              {showHelp && (
                <div className="token-help">
                  {TOKEN_HELP[form.platform] || 'No instructions available for this platform.'}
                </div>
              )}
            </div>
          </div>
          <button className="btn btn-cyan" type="submit" disabled={saving}>
            {saving ? 'SAVING...' : 'ADD ACCOUNT'}
          </button>
        </form>
      )}

      {/* Table */}
      {accounts.length === 0 ? (
        <div className="empty-state">NO ACCOUNTS REGISTERED</div>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>PLATFORM</th>
              <th>USERNAME</th>
              <th>DISPLAY NAME</th>
              <th>STATUS</th>
              <th>LAST CHECKED</th>
              <th>ACTIONS</th>
            </tr>
          </thead>
          <tbody>
            {accounts.map(acc => (
              <tr key={acc.id}>
                <td>
                  <span className="platform-icon-small">{PLATFORM_ICONS_SMALL[acc.platform] || '🔗'}</span>
                  {acc.platform.toUpperCase()}
                </td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>{editId === acc.id
                  ? <input className="form-input form-input-sm" value={editForm.username} onChange={e => setEditForm({ ...editForm, username: e.target.value })} />
                  : acc.username
                }</td>
                <td>{editId === acc.id
                  ? <input className="form-input form-input-sm" value={editForm.display_name} onChange={e => setEditForm({ ...editForm, display_name: e.target.value })} />
                  : acc.display_name || '—'
                }</td>
                <td>
                  {editId === acc.id ? (
                    <select className="form-input form-input-sm form-select" value={editForm.status} onChange={e => setEditForm({ ...editForm, status: e.target.value })}>
                      {['active', 'monitoring', 'suspended', 'compromised'].map(s => <option key={s} value={s}>{s.toUpperCase()}</option>)}
                    </select>
                  ) : (
                    <span className="status-badge" style={{ color: STATUS_COLORS[acc.status] || 'var(--text-muted)', borderColor: STATUS_COLORS[acc.status] || 'var(--border)' }}>
                      {(acc.status || 'unknown').toUpperCase()}
                    </span>
                  )}
                </td>
                <td className="text-muted">
                  {acc.last_checked_at ? new Date(acc.last_checked_at).toLocaleString('en-GB', { hour12: false }) : 'never'}
                </td>
                <td>
                  {editId === acc.id ? (
                    <div style={{ display: 'flex', gap: 4 }}>
                      <button className="btn btn-cyan btn-sm" onClick={() => handleEdit(acc.id)} disabled={saving}>SAVE</button>
                      <button className="btn btn-muted btn-sm" onClick={() => setEditId(null)}>CANCEL</button>
                    </div>
                  ) : (
                    <div style={{ display: 'flex', gap: 4 }}>
                      <button className="btn btn-muted btn-sm" onClick={() => startEdit(acc)}>EDIT</button>
                      <button className="btn btn-red btn-sm" onClick={() => handleDelete(acc.id)}>DELETE</button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

const PLATFORM_ICONS_SMALL = {
  facebook: '📘', instagram: '📷', twitter: '🐦',
  linkedin: '💼', tiktok: '🎵', youtube: '▶️',
}
