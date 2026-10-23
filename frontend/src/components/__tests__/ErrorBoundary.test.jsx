import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import ErrorBoundary from '../ErrorBoundary'

function Broken() {
  throw new Error('intentional test error')
}

function Fine() {
  return <div>everything is fine</div>
}

describe('ErrorBoundary', () => {
  it('renders children normally when nothing throws', () => {
    render(
      <ErrorBoundary>
        <Fine />
      </ErrorBoundary>
    )
    expect(screen.getByText('everything is fine')).toBeInTheDocument()
  })

  it('catches a thrown render error and shows the fallback instead of crashing', () => {
    // React logs the error to console.error even when caught by a
    // boundary — silence it for this test so the expected error
    // doesn't look like a test failure in output.
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    render(
      <ErrorBoundary>
        <Broken />
      </ErrorBoundary>
    )

    expect(screen.getByText('Something went wrong')).toBeInTheDocument()
    expect(screen.getByText('Reload')).toBeInTheDocument()
    // The broken component's own output must NOT be in the DOM —
    // confirms the boundary actually replaced it, not just added to it.
    expect(screen.queryByText('everything is fine')).not.toBeInTheDocument()

    consoleSpy.mockRestore()
  })

  it('reload button calls window.location.reload', () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const reloadSpy = vi.fn()
    const originalLocation = window.location
    delete window.location
    window.location = { ...originalLocation, reload: reloadSpy }

    render(
      <ErrorBoundary>
        <Broken />
      </ErrorBoundary>
    )
    screen.getByText('Reload').click()
    expect(reloadSpy).toHaveBeenCalled()

    window.location = originalLocation
    consoleSpy.mockRestore()
  })
})
