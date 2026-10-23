import { useState, Suspense, lazy } from 'react'
import { Routes, Route, useLocation } from 'react-router-dom'
import { AuthProvider, useAuth } from './hooks/useAuth'
import { DomainProvider } from './hooks/useDomain'
import { ToastProvider } from './components/Toast'
import { ModalProvider } from './components/Modal'
import Sidebar from './components/Sidebar'
import Topbar from './components/Topbar'
import ErrorBoundary from './components/ErrorBoundary'

// Lazy-loaded so a visitor only downloads the page they're actually on
// — see docs/AUDIT.md 3.4. Before this, all 7 pages (charts, tables,
// every modal body) shipped in one bundle regardless of which single
// page loaded first.
const Overview = lazy(() => import('./pages/Overview'))
const Analytics = lazy(() => import('./pages/Analytics'))
const Domains = lazy(() => import('./pages/Domains'))
const Crawlers = lazy(() => import('./pages/Crawlers'))
const WAF = lazy(() => import('./pages/WAF'))
const Settings = lazy(() => import('./pages/Settings'))

const TITLES = {
  '/': 'Dashboard',
  '/analytics': 'Analytics',
  '/domains': 'Domains',
  '/crawlers': 'Crawlers',
  '/waf': 'WAF',
  '/settings': 'Settings',
}

function Shell() {
  const { loading } = useAuth()
  const location = useLocation()
  const [refreshKey, setRefreshKey] = useState(0)
  const [sidebarOpen, setSidebarOpen] = useState(false)

  if (loading) {
    return <div className="empty" style={{ padding: 60 }}>Loading…</div>
  }

  return (
    <DomainProvider>
      <div className="shell">
        <Sidebar mobileOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />
        <div className="main">
          <Topbar
            title={TITLES[location.pathname] || 'Dashboard'}
            onRefresh={() => setRefreshKey((k) => k + 1)}
            onMenuClick={() => setSidebarOpen(true)}
          />
          <div className="content">
            <ErrorBoundary key={location.pathname}>
              <Suspense fallback={<div className="empty" style={{ padding: 60 }}>Loading…</div>}>
                <Routes>
                  <Route path="/" element={<Overview refreshKey={refreshKey} />} />
                  <Route path="/analytics" element={<Analytics refreshKey={refreshKey} />} />
                  <Route path="/domains" element={<Domains refreshKey={refreshKey} />} />
                  <Route path="/crawlers" element={<Crawlers refreshKey={refreshKey} />} />
                  <Route path="/waf" element={<WAF refreshKey={refreshKey} />} />
                  <Route path="/settings" element={<Settings refreshKey={refreshKey} />} />
                </Routes>
              </Suspense>
            </ErrorBoundary>
          </div>
        </div>
      </div>
    </DomainProvider>
  )
}

export default function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <ToastProvider>
          <ModalProvider>
            <Shell />
          </ModalProvider>
        </ToastProvider>
      </AuthProvider>
    </ErrorBoundary>
  )
}
