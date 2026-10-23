/**
 * API client. Auth now rides on an httpOnly session cookie the browser
 * sends automatically — the JWT is never stored in localStorage or
 * touched by this file at all (see docs/AUDIT.md 3.3). The only thing
 * this file still manages client-side is the CSRF token: it's
 * deliberately NOT httpOnly, specifically so this code can read it and
 * echo it back as a header on mutating requests — that's the whole
 * double-submit mechanism (see the comment above set_session_cookies
 * in backend/app/api/auth.py for the full explanation).
 */

const CSRF_EXEMPT_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', undefined])

function getCsrfCookie() {
  const match = document.cookie.match(/(?:^|;\s*)cb_csrf=([^;]+)/)
  return match ? decodeURIComponent(match[1]) : ''
}

export function clearSession() {
  // Nothing to clear client-side anymore — the cookies are httpOnly
  // (session) or cleared by the server's own /api/auth/logout response
  // (both). Kept as a named export so callers don't need to know that.
}

async function requestApi(url, options = {}) {
  const method = (options.method || 'GET').toUpperCase()
  const headers = {
    ...(options.body ? { 'Content-Type': 'application/json' } : {}),
    ...(!CSRF_EXEMPT_METHODS.has(method) ? { 'X-CSRF-Token': getCsrfCookie() } : {}),
    ...(options.headers || {}),
  }
  const response = await fetch(url, { ...options, headers, credentials: 'same-origin' })
  if (response.status === 401) {
    window.location.replace('/login.html')
    return null
  }
  const data = await response.json().catch(() => null)
  if (!response.ok) {
    const detail = data?.detail
    const message = typeof detail === 'object' ? detail?.message : detail
    throw new Error(message || 'Request failed')
  }
  return data
}

export const api = {
  get: (url) => requestApi(url).catch(() => null),
  post: (url, body) => requestApi(url, { method: 'POST', body: body !== undefined ? JSON.stringify(body) : undefined }),
  put: (url, body) => requestApi(url, { method: 'PUT', body: JSON.stringify(body) }),
  del: (url, body) => requestApi(url, { method: 'DELETE', body: body !== undefined ? JSON.stringify(body) : undefined }),
}
