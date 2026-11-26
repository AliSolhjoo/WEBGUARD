const API = '/api/v1'

type TokenPair = { access: string; refresh: string }

let refreshInFlight: Promise<boolean> | null = null

export function saveTokens(tokens: TokenPair) {
  // Session-only storage limits persistence; production should prefer HttpOnly Secure cookies / BFF.
  sessionStorage.setItem('wg_access', tokens.access)
  sessionStorage.setItem('wg_refresh', tokens.refresh)
}
export function clearTokens() {
  sessionStorage.removeItem('wg_access')
  sessionStorage.removeItem('wg_refresh')
}
export function hasSession() {
  return Boolean(sessionStorage.getItem('wg_access'))
}

async function refreshAccess(): Promise<boolean> {
  if (refreshInFlight) return refreshInFlight
  const refresh = sessionStorage.getItem('wg_refresh')
  if (!refresh) return false
  refreshInFlight = (async () => {
    try {
      const response = await fetch(`${API}/auth/refresh/`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ refresh })
      })
      if (!response.ok) return false
      const data = await response.json()
      sessionStorage.setItem('wg_access', data.access)
      if (data.refresh) sessionStorage.setItem('wg_refresh', data.refresh)
      return true
    } catch { return false }
    finally { refreshInFlight = null }
  })()
  return refreshInFlight
}

export async function api<T>(path: string, options: RequestInit = {}, retried = false): Promise<T> {
  const headers = new Headers(options.headers)
  const access = sessionStorage.getItem('wg_access')
  if (access) headers.set('Authorization', `Bearer ${access}`)
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json')
  const response = await fetch(`${API}${path}`, { ...options, headers })
  if (response.status === 401 && !retried) {
    if (await refreshAccess()) return api<T>(path, options, true)
    clearTokens()
    throw new Error('Your session expired. Please sign in again.')
  }
  if (response.status === 401 && retried) clearTokens()
  if (!response.ok) {
    let message = `Request failed (${response.status})`
    try {
      const body = await response.json()
      message = typeof body.detail === 'string' ? body.detail : Object.entries(body).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : String(v)}`).join(' | ')
    } catch { /* response did not contain JSON */ }
    throw new Error(message)
  }
  if (response.status === 204) return undefined as T
  const contentType = response.headers.get('content-type') || ''
  if (contentType.includes('application/json')) return response.json() as Promise<T>
  return response as unknown as T
}

export async function downloadReport(id: number) {
  const response = await api<Response>(`/reports/${id}/download/`)
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `webguard-report-${id}.pdf`
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export async function revokeServerSession(): Promise<void> {
  let access = sessionStorage.getItem('wg_access')
  let refresh = sessionStorage.getItem('wg_refresh')
  if (!access || !refresh) return

  const sendLogout = () => fetch(`${API}/auth/logout/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${access}` },
    body: JSON.stringify({ refresh })
  })

  let response = await sendLogout()
  if (response.status === 401 && await refreshAccess()) {
    access = sessionStorage.getItem('wg_access')
    refresh = sessionStorage.getItem('wg_refresh')
    if (access && refresh) response = await sendLogout()
  }
  if (!response.ok && response.status !== 401) throw new Error('Server-side session revocation failed.')
}
