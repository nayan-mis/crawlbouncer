import { NavLink, useLocation } from 'react-router-dom'
import { useEffect } from 'react'
import { useDomain } from '../hooks/useDomain'

const NAV = [
  { section: 'Overview', items: [
    { to: '/', label: 'Dashboard', icon: <path d="M1 1h5v5H1zM8 1h5v5H8zM1 8h5v5H1zM8 8h5v5H8z" /> },
    { to: '/analytics', label: 'Analytics', icon: <path d="M1 10.5L4.5 6.5 7 9 10.5 4 13 6M1 13h12" /> },
  ]},
  { section: 'Manage', items: [
    { to: '/domains', label: 'Domains', icon: <path d="M7 1.5c-1.8 1.8-2.5 3.5-2.5 5.5S5.2 10.7 7 12.5c1.8-1.8 2.5-3.5 2.5-5.5S8.8 1.5 7 1.5zM1.5 7h11" /> },
    { to: '/crawlers', label: 'Crawlers', icon: <path d="M2 4h10v7.5H2z" /> },
  ]},
  { section: 'Security', items: [
    { to: '/waf', label: 'WAF', icon: <path d="M7 1L2 3.5v3.5C2 10.3 4.2 12.8 7 13.5c2.8-.7 5-3.2 5-6.5V3.5L7 1z" /> },
    { to: '/settings', label: 'Settings', icon: <path d="M7 1v1.5M7 11.5V13M1 7h1.5M11.5 7H13" /> },
  ]},
]

export default function Sidebar({ mobileOpen = false, onClose = () => {} }) {
  const { currentDomain } = useDomain()
  const location = useLocation()

  // Below 680px the sidebar is otherwise unreachable — closing it on
  // every navigation means a route change (from tapping a NavLink)
  // dismisses the drawer automatically, instead of leaving it open
  // over the newly-loaded page underneath.
  useEffect(() => { onClose() }, [location.pathname])

  return (
    <>
      {mobileOpen && <div className="sidebar-backdrop" onClick={onClose} />}
      <nav className={`sidebar${mobileOpen ? ' mobile-open' : ''}`}>
        <div className="sb-logo">
          <div className="sb-logomark">
            <svg viewBox="0 0 10 10"><path d="M1 2h8M1 5h5M1 8h7" /><circle cx="8" cy="8" r="1.5" fill="white" /></svg>
          </div>
          <span className="sb-name">CrawlBouncer</span>
          <button className="sidebar-close" onClick={onClose} aria-label="Close menu">
            <svg viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4"><line x1="2" y1="2" x2="12" y2="12" /><line x1="12" y1="2" x2="2" y2="12" /></svg>
          </button>
        </div>

        {NAV.map((group) => (
          <div key={group.section}>
            <div className="sb-section">{group.section}</div>
            {group.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                className={({ isActive }) => `sb-item${isActive ? ' on' : ''}`}
              >
                <svg viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4">{item.icon}</svg>
                {item.label}
              </NavLink>
            ))}
          </div>
        ))}

        <div className="sb-foot">
          <div className="sb-domain">
            <div className="sb-dot" />
            <span className="sb-domain-name">{currentDomain ? currentDomain.domain : 'No domain added yet'}</span>
          </div>
        </div>
      </nav>
    </>
  )
}
