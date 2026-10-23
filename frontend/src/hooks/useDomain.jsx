import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { api } from '../api/client'

const DomainContext = createContext(null)

export function DomainProvider({ children }) {
  const [domains, setDomains] = useState([])
  const [currentDomain, setCurrentDomain] = useState(null)
  const [loaded, setLoaded] = useState(false)

  const refresh = useCallback(async () => {
    const list = await api.get('/api/domains/')
    setDomains(list || [])
    setCurrentDomain((prev) => {
      if (prev && (list || []).some((d) => d.id === prev.id)) return prev
      return (list && list[0]) || null
    })
    setLoaded(true)
  }, [])

  useEffect(() => { refresh() }, [refresh])

  return (
    <DomainContext.Provider value={{ domains, currentDomain, setCurrentDomain, refresh, loaded }}>
      {children}
    </DomainContext.Provider>
  )
}

export function useDomain() {
  const ctx = useContext(DomainContext)
  if (!ctx) throw new Error('useDomain must be used within DomainProvider')
  return ctx
}
