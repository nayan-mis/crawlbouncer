import { useEffect, useState } from 'react'

const THEME_KEY = 'cb_theme'

function systemPrefersDark() {
  return typeof window !== 'undefined' && window.matchMedia
    ? window.matchMedia('(prefers-color-scheme: dark)').matches
    : true
}

export default function Topbar({ title, onRefresh, rightAction, onMenuClick }) {
  // The dashboard theme follows the OS/browser color-scheme setting by
  // default — same as the marketing site's existing
  // `@media(prefers-color-scheme: dark)` rule in site.css — rather
  // than always forcing dark regardless of what the system is set to.
  // A stored value only exists once the person has explicitly used
  // the toggle below; until then this stays in sync with the system
  // setting live, including if it changes while the tab is open.
  const [theme, setThemeState] = useState(() => {
    const stored = localStorage.getItem(THEME_KEY)
    return stored || (systemPrefersDark() ? 'dark' : 'light')
  })
  const [hasManualOverride, setHasManualOverride] = useState(
    () => localStorage.getItem(THEME_KEY) !== null
  )

  useEffect(() => {
    document.documentElement.dataset.theme = theme
  }, [theme])

  useEffect(() => {
    if (hasManualOverride || !window.matchMedia) return
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = (e) => setThemeState(e.matches ? 'dark' : 'light')
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [hasManualOverride])

  function toggleTheme() {
    const next = theme === 'dark' ? 'light' : 'dark'
    setThemeState(next)
    setHasManualOverride(true)
    localStorage.setItem(THEME_KEY, next)
  }

  return (
    <div className="topbar">
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <button className="icon-btn menu-btn" onClick={onMenuClick} aria-label="Open menu">
          <svg viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4">
            <line x1="1" y1="3.5" x2="13" y2="3.5" /><line x1="1" y1="7" x2="13" y2="7" /><line x1="1" y1="10.5" x2="13" y2="10.5" />
          </svg>
        </button>
        <span className="tb-title">{title}</span>
        <div className="live-pill"><div className="live-pulse" />Live</div>
      </div>
      <div className="tb-right">
        <button className="icon-btn" onClick={toggleTheme} title="Toggle theme">
          <svg viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4">
            <circle cx="7" cy="7" r="3" />
            <line x1="7" y1="1" x2="7" y2="2.5" /><line x1="7" y1="11.5" x2="7" y2="13" />
            <line x1="1" y1="7" x2="2.5" y2="7" /><line x1="11.5" y1="7" x2="13" y2="7" />
          </svg>
        </button>
        <button className="btn btn-outline" onClick={onRefresh}>
          <svg viewBox="0 0 13 13" fill="none" stroke="currentColor" strokeWidth="1.4"><path d="M1 6.5A5.5 5.5 0 1 0 6.5 1" /><polyline points="1,1 1,6.5 6.5,6.5" /></svg>
          Refresh
        </button>
        {rightAction}
      </div>
    </div>
  )
}
