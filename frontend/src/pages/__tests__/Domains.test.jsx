import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import Domains from '../Domains'
import { DomainProvider } from '../../hooks/useDomain'
import { ModalProvider } from '../../components/Modal'
import { ToastProvider } from '../../components/Toast'

function renderDomains(props = {}) {
  return render(
    <ToastProvider>
      <ModalProvider>
        <DomainProvider>
          <Domains {...props} />
        </DomainProvider>
      </ModalProvider>
    </ToastProvider>
  )
}

/** Minimal fetch mock router keyed on method+path, matching what
 * Domains.jsx / useDomain.jsx actually call — not a generic passthrough,
 * so a test only needs to stub the calls its own flow will make. */
function mockFetch(routes) {
  return vi.fn((url, options = {}) => {
    const method = (options.method || 'GET').toUpperCase()
    const key = `${method} ${url}`
    const handler = routes[key] ?? routes[url]
    if (!handler) {
      throw new Error(`Unmocked fetch call: ${key}`)
    }
    const body = typeof handler === 'function' ? handler(options) : handler
    return Promise.resolve({
      status: 200,
      ok: true,
      json: () => Promise.resolve(body),
    })
  })
}

const REVERSE_PROXY_DOMAIN = {
  id: 'dom-rp-1', domain: 'reverseproxysite.com', integration_mode: 'reverse_proxy',
  origin_url: 'https://origin.example.com', dns_verified: true, ssl_active: true,
  cname_target: 'edge.example.com', created_at: '2026-01-01',
}

const BOLT_ON_DOMAIN = {
  id: 'dom-bo-1', domain: 'boltonsite.com', integration_mode: 'bolt_on',
  origin_url: null, dns_verified: true, ssl_active: true,
  cname_target: null, created_at: '2026-01-02',
}

beforeEach(() => {
  document.cookie = 'cb_csrf=test-token'
})

afterEach(() => {
  vi.restoreAllMocks()
  document.cookie = 'cb_csrf=; expires=Thu, 01 Jan 1970 00:00:00 UTC'
})

describe('Domains table — bolt-on vs reverse-proxy rendering', () => {
  it('shows Mode badges, N/A for DNS on bolt-on, and the right action button per row', async () => {
    global.fetch = mockFetch({
      'GET /api/domains/': [REVERSE_PROXY_DOMAIN, BOLT_ON_DOMAIN],
      'GET /api/mirror/dom-rp-1': { overrides: [] },
      'GET /api/rules/dom-rp-1/paths': [],
    })

    renderDomains()

    await waitFor(() => expect(screen.getByText('reverseproxysite.com')).toBeInTheDocument())
    expect(screen.getByText('boltonsite.com')).toBeInTheDocument()

    expect(screen.getByText('Reverse proxy')).toBeInTheDocument()
    expect(screen.getByText('Bolt-on')).toBeInTheDocument()

    const boltOnRow = screen.getByText('boltonsite.com').closest('tr')
    const rpRow = screen.getByText('reverseproxysite.com').closest('tr')

    // Bolt-on row: N/A (DNS), "View integration" button, no "Verify DNS"
    expect(within(boltOnRow).getAllByText('N/A')).toHaveLength(1)
    expect(within(boltOnRow).getByText('View integration')).toBeInTheDocument()
    expect(within(boltOnRow).queryByText('Verify DNS')).not.toBeInTheDocument()

    // Reverse-proxy row (already DNS-verified in this fixture): no N/A,
    // no "View integration", and since dns_verified is true, no "Verify
    // DNS" button either (regression check: bolt-on logic must not leak
    // into the reverse-proxy branch).
    expect(within(rpRow).queryByText('N/A')).not.toBeInTheDocument()
    expect(within(rpRow).queryByText('View integration')).not.toBeInTheDocument()
    expect(within(rpRow).getByText('Verified')).toBeInTheDocument()
  })

  it('shows a "Verify DNS" button on a reverse-proxy domain that is not yet DNS-verified', async () => {
    const unverified = { ...REVERSE_PROXY_DOMAIN, id: 'dom-rp-2', domain: 'unverified.com', dns_verified: false, ssl_active: false }
    global.fetch = mockFetch({
      'GET /api/domains/': [unverified],
      'GET /api/mirror/dom-rp-2': { overrides: [] },
      'GET /api/rules/dom-rp-2/paths': [],
    })

    renderDomains()

    await waitFor(() => expect(screen.getByText('unverified.com')).toBeInTheDocument())
    const row = screen.getByText('unverified.com').closest('tr')
    expect(within(row).getByText('Verify DNS')).toBeInTheDocument()
  })
})

describe('Add domain modal — mode selector', () => {
  it('hides the origin URL field when bolt-on is selected, shows it for reverse-proxy', async () => {
    global.fetch = mockFetch({ 'GET /api/domains/': [] })
    renderDomains()

    await waitFor(() => expect(screen.getByText('No domains yet')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Add domain'))

    // Default is reverse_proxy — origin field visible.
    expect(screen.getByPlaceholderText('https://your-origin-server.com')).toBeInTheDocument()

    fireEvent.change(document.getElementById('dm-mode'), { target: { value: 'bolt_on' } })

    expect(screen.queryByPlaceholderText('https://your-origin-server.com')).not.toBeInTheDocument()
    expect(screen.getByText(/Doesn't include WAF\/DDoS protection/)).toBeInTheDocument()
  })

  it('submitting bolt-on mode calls the API without origin_url and shows the one-time edge-key modal', async () => {
    const postSpy = vi.fn(() => ({
      id: 'dom-new', domain: 'newbolton.com', integration_mode: 'bolt_on',
      edge_api_key: 'cb_edge_TESTKEY123', dns_verified: true, ssl_active: true,
    }))
    global.fetch = mockFetch({
      'GET /api/domains/': () => [],
      'POST /api/domains/': (options) => {
        const body = JSON.parse(options.body)
        expect(body).toEqual({ domain: 'newbolton.com', integration_mode: 'bolt_on' })
        return postSpy()
      },
    })

    renderDomains()
    await waitFor(() => expect(screen.getByText('No domains yet')).toBeInTheDocument())

    fireEvent.click(screen.getByText('Add domain'))
    fireEvent.change(document.getElementById('nd'), { target: { value: 'newbolton.com' } })
    fireEvent.change(document.getElementById('dm-mode'), { target: { value: 'bolt_on' } })
    fireEvent.click(within(document.querySelector('.modal-ft')).getByText('Add domain'))

    await waitFor(() => expect(screen.getByText('cb_edge_TESTKEY123')).toBeInTheDocument())
    expect(screen.getByText(/shown/i)).toBeInTheDocument()
    expect(postSpy).toHaveBeenCalled()
  })

  it('submitting reverse-proxy mode without a valid origin URL is rejected client-side (no API call made)', async () => {
    const fetchMock = mockFetch({ 'GET /api/domains/': () => [] })
    global.fetch = fetchMock
    renderDomains()

    await waitFor(() => expect(screen.getByText('No domains yet')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Add domain'))
    fireEvent.change(document.getElementById('nd'), { target: { value: 'badorigin.com' } })
    fireEvent.change(document.getElementById('no'), { target: { value: 'not-a-url' } })
    fireEvent.click(within(document.querySelector('.modal-ft')).getByText('Add domain'))

    // Only the initial GET should have fired — no POST for the rejected submission.
    await new Promise((r) => setTimeout(r, 10))
    const postCalls = fetchMock.mock.calls.filter(([, opts]) => opts?.method === 'POST')
    expect(postCalls).toHaveLength(0)
  })
})

describe('Bolt-on "View integration" modal', () => {
  it('opens the instructions modal with the decide endpoint', async () => {
    global.fetch = mockFetch({
      'GET /api/domains/': [BOLT_ON_DOMAIN],
      'GET /api/mirror/dom-bo-1': { overrides: [] },
      'GET /api/rules/dom-bo-1/paths': [],
    })

    renderDomains()
    await waitFor(() => expect(screen.getByText('boltonsite.com')).toBeInTheDocument())

    fireEvent.click(screen.getByText('View integration'))

    expect(await screen.findByText('POST /v1/decide')).toBeInTheDocument()
    expect(screen.getByText(/integrations\/bolt-on/)).toBeInTheDocument()
  })
})

describe('Remove domain', () => {
  it('does nothing if the confirm dialog is declined', async () => {
    const fetchMock = mockFetch({
      'GET /api/domains/': [BOLT_ON_DOMAIN],
      'GET /api/mirror/dom-bo-1': { overrides: [] },
      'GET /api/rules/dom-bo-1/paths': [],
    })
    global.fetch = fetchMock
    vi.spyOn(window, 'confirm').mockReturnValue(false)

    renderDomains()
    await waitFor(() => expect(screen.getByText('boltonsite.com')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Remove'))

    await new Promise((r) => setTimeout(r, 10))
    const deleteCalls = fetchMock.mock.calls.filter(([, opts]) => opts?.method === 'DELETE')
    expect(deleteCalls).toHaveLength(0)
  })

  it('calls DELETE and refreshes when confirmed', async () => {
    let deleted = false
    global.fetch = mockFetch({
      'GET /api/domains/': () => (deleted ? [] : [BOLT_ON_DOMAIN]),
      'GET /api/mirror/dom-bo-1': { overrides: [] },
      'GET /api/rules/dom-bo-1/paths': [],
      'DELETE /api/domains/dom-bo-1': () => { deleted = true; return { message: 'ok' } },
    })
    vi.spyOn(window, 'confirm').mockReturnValue(true)

    renderDomains()
    await waitFor(() => expect(screen.getByText('boltonsite.com')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Remove'))

    await waitFor(() => expect(screen.getByText('No domains yet')).toBeInTheDocument())
  })
})
