import { createContext, useContext, useEffect, useState } from 'react'
import { api } from '../api/client'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [me, setMe] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // No client-side check for "is there a token" anymore — the
    // session cookie is httpOnly, so JS can't see it either way.
    // Just ask the API; a 401 here is handled by client.js's own
    // interceptor, which redirects to /login.html.
    api.get('/api/auth/me').then((data) => {
      setMe(data)
      setLoading(false)
    })
  }, [])

  async function logout() {
    try {
      await api.post('/api/auth/logout')
    } finally {
      window.location.replace('/login.html')
    }
  }

  return (
    <AuthContext.Provider value={{ me, setMe, loading, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
