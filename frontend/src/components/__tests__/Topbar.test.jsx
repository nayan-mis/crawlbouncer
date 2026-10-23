import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, act } from '@testing-library/react'
import Topbar from '../Topbar'

/** Mock matchMedia so tests control the "system" color-scheme
 * directly, rather than depending on whatever environment vitest
 * happens to run in. */
function mockMatchMedia(prefersDark) {
  const listeners = []
  window.matchMedia = vi.fn().mockImplementation((query) => ({
    matches: query === '(prefers-color-scheme: dark)' ? prefersDark : false,
    media: query,
    addEventListener: (event, cb) => listeners.push(cb),
    removeEventListener: () => {},
    // exposed for tests to simulate a live system change
    _fire: (matches) => listeners.forEach((cb) => cb({ matches })),
  }))
  return () => window.matchMedia('(prefers-color-scheme: dark)')
}

beforeEach(() => {
  localStorage.clear()
  delete document.documentElement.dataset.theme
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('Topbar theme — follows the system by default', () => {
  it('defaults to dark when the system prefers dark and nothing is stored', () => {
    mockMatchMedia(true)
    render(<Topbar title="Domains" />)
    expect(document.documentElement.dataset.theme).toBe('dark')
  })

  it('defaults to light when the system prefers light and nothing is stored', () => {
    mockMatchMedia(false)
    render(<Topbar title="Domains" />)
    expect(document.documentElement.dataset.theme).toBe('light')
  })

  it('a stored preference overrides the system setting', () => {
    mockMatchMedia(true) // system says dark
    localStorage.setItem('cb_theme', 'light') // but the user chose light before
    render(<Topbar title="Domains" />)
    expect(document.documentElement.dataset.theme).toBe('light')
  })

  it('manually toggling sets data-theme, persists it, and stops following the system', () => {
    const getMq = mockMatchMedia(false) // system: light
    render(<Topbar title="Domains" />)
    expect(document.documentElement.dataset.theme).toBe('light')

    fireEvent.click(screen.getByTitle('Toggle theme'))
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(localStorage.getItem('cb_theme')).toBe('dark')

    // System now "changes" to dark too — since the user already made
    // an explicit choice, that choice must stick rather than being
    // silently overridden by a system-level change afterward.
    act(() => { getMq()._fire(true) })
    expect(document.documentElement.dataset.theme).toBe('dark')
  })

  it('without a manual override, a live system change updates the theme', () => {
    const getMq = mockMatchMedia(false)
    render(<Topbar title="Domains" />)
    expect(document.documentElement.dataset.theme).toBe('light')

    act(() => { getMq()._fire(true) })
    expect(document.documentElement.dataset.theme).toBe('dark')
  })
})
