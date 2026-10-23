import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { useDomain } from '../hooks/useDomain'
import { useModal } from '../components/Modal'
import { useToast } from '../components/Toast'
import { StatusBadge, ActionBadge, ModeBadge } from '../components/Badge'

export default function Domains({ refreshKey }) {
  const { domains, currentDomain, refresh } = useDomain()
  const notify = useToast()
  const { showModal, closeModal } = useModal()

  useEffect(() => { refresh() }, [refreshKey, refresh])

  async function removeDomain(id, domain) {
    if (!window.confirm(`Remove ${domain}?`)) return
    await api.del(`/api/domains/${id}`)
    notify(`${domain} removed`)
    refresh()
  }

  function openVerify(id, domain, cname) {
    showModal(`DNS — ${domain}`, <VerifyBody id={id} cname={cname} onVerified={() => { refresh() }} />,
      [{ label: 'Close', cls: 'btn-outline', fn: closeModal }])
  }

  function openEdgeKey(domain, edgeKey) {
    showModal(`Bolt-on — ${domain}`, <EdgeKeyBody domain={domain} edgeKey={edgeKey} />,
      [{ label: 'Done', cls: 'btn-default', fn: closeModal }])
  }

  function openBoltOnInstructions(domain) {
    showModal(`Integration — ${domain.domain}`, <BoltOnInstructionsBody />,
      [{ label: 'Close', cls: 'btn-outline', fn: closeModal }])
  }

  function openAddDomain() {
    showModal('Add domain', <AddDomainBody />, [
      { label: 'Cancel', cls: 'btn-outline', fn: closeModal },
      { label: 'Add domain', cls: 'btn-default', fn: async () => {
        const domain = document.getElementById('nd').value.trim().replace(/^https?:\/\//, '')
        const mode = document.getElementById('dm-mode').value
        if (!domain) return notify('Enter a domain name')

        if (mode === 'bolt_on') {
          try {
            const res = await api.post('/api/domains/', { domain, integration_mode: 'bolt_on' })
            closeModal(); notify(`${domain} added`); await refresh()
            openEdgeKey(res.domain, res.edge_api_key)
          } catch (e) { notify(e.message || 'Failed') }
          return
        }

        const origin = document.getElementById('no').value.trim()
        if (!origin.startsWith('http')) return notify('Origin must start with https://')
        try {
          const res = await api.post('/api/domains/', { domain, origin_url: origin })
          closeModal(); notify(`${domain} added`); await refresh()
          openVerify(res.id, res.domain, res.cname_target)
        } catch (e) { notify(e.message || 'Failed') }
      }},
    ])
  }

  return (
    <>
      <div className="page-header">
        <div className="page-title">Domains</div>
        <div className="page-sub">Websites protected by CrawlBouncer.</div>
      </div>

      <div className="panel">
        <div className="tbl-wrap">
          <table>
            <thead><tr><th>Domain</th><th>Mode</th><th>DNS</th><th>Origin</th><th>Added</th><th></th></tr></thead>
            <tbody>
              {domains.length ? domains.map((d) => (
                <tr key={d.id}>
                  <td className="t1 mono">{d.domain}</td>
                  <td><ModeBadge mode={d.integration_mode} /></td>
                  <td>{d.integration_mode === 'bolt_on' ? <span className="badge b-neutral">N/A</span> : <StatusBadge ok={d.dns_verified} />}</td>
                  <td className="mono" style={{ color: 'var(--t3)', fontSize: 11, maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.origin_url || '—'}</td>
                  <td style={{ color: 'var(--t3)', fontSize: 11.5 }}>{(d.created_at || '').slice(0, 10)}</td>
                  <td style={{ textAlign: 'right' }}>
                    <div style={{ display: 'flex', gap: 4, justifyContent: 'flex-end' }}>
                      {d.integration_mode === 'bolt_on'
                        ? <button className="btn btn-outline" style={{ fontSize: 11.5, padding: '3px 8px' }} onClick={() => openBoltOnInstructions(d)}>View integration</button>
                        : !d.dns_verified && <button className="btn btn-outline" style={{ fontSize: 11.5, padding: '3px 8px' }} onClick={() => openVerify(d.id, d.domain, d.cname_target)}>Verify DNS</button>}
                      <button className="btn btn-ghost" style={{ fontSize: 11.5, color: 'var(--red)' }} onClick={() => removeDomain(d.id, d.domain)}>Remove</button>
                    </div>
                  </td>
                </tr>
              )) : (
                <tr><td colSpan={7}>
                  <div className="empty">
                    <div className="empty-title">No domains yet</div>
                    <div className="empty-sub">Add your first domain to start protecting it.</div>
                    <button className="btn btn-default" style={{ marginTop: 8 }} onClick={openAddDomain}>Add domain</button>
                  </div>
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {domains.length > 0 && (
        <div style={{ marginTop: 12, display: 'flex', justifyContent: 'flex-end' }}>
          <button className="btn btn-outline" onClick={openAddDomain}>+ Add domain</button>
        </div>
      )}

      {currentDomain && (
        <>
          <AgentMirrorSection domain={currentDomain} />
          <PathRulesSection domain={currentDomain} />
        </>
      )}
    </>
  )
}

function AddDomainBody() {
  const [mode, setMode] = useState('reverse_proxy')
  return (
    <>
      <div className="input-group">
        <label className="input-label">Domain</label>
        <input className="input" id="nd" placeholder="yourblog.com" />
        <div className="input-hint">Enter the domain without https://</div>
      </div>
      <div className="input-group">
        <label className="input-label">Integration</label>
        <select className="input" id="dm-mode" value={mode} onChange={(e) => setMode(e.target.value)}>
          <option value="reverse_proxy">Reverse proxy — CrawlBouncer sits in front via CNAME (recommended)</option>
          <option value="bolt_on">Bolt-on — keep your existing CDN/DNS, call CrawlBouncer from your own server</option>
        </select>
        <div className="input-hint">
          {mode === 'bolt_on'
            ? "No DNS change. Your own server calls CrawlBouncer's /v1/decide before serving each request and enforces the result. Doesn't include WAF/DDoS protection — that stays your CDN's job."
            : "CrawlBouncer sees and gates every request itself once DNS is verified. Full protection: WAF, DDoS, bot detection, all in-path."}
        </div>
      </div>
      {mode === 'reverse_proxy' && (
        <div className="input-group">
          <label className="input-label">Origin server URL</label>
          <input className="input" id="no" placeholder="https://your-origin-server.com" />
          <div className="input-hint">Where your site currently lives. CrawlBouncer proxies to this after security checks.</div>
        </div>
      )}
    </>
  )
}

function EdgeKeyBody({ domain, edgeKey }) {
  return (
    <>
      <p style={{ fontSize: 12.5, color: 'var(--t2)', marginBottom: 14 }}>
        {domain} is set up for bolt-on integration. This key is shown <strong>once</strong> — store it
        somewhere safe now. If it's lost, the domain will need to be removed and re-added to get a new one.
      </p>
      <div className="dns-block">
        <span className="mono" style={{ wordBreak: 'break-all' }}>{edgeKey}</span>
        <CopyButton text={edgeKey} />
      </div>
      <div className="dns-row" style={{ paddingBottom: 0 }}>
        <div className="dns-row-inner">
          <div style={{ flex: 1 }}>
            <div className="dns-label">Next step</div>
            <div className="dns-hint" style={{ marginTop: 4 }}>
              Have your own server call <code>POST /v1/decide</code> with header{' '}
              <code>X-Edge-Key: {'{key above}'}</code> before serving each request, and enforce whatever
              it returns (allow / block). Same bot detection and rules as
              reverse-proxy mode — this mode only moves who enforces the decision.
            </div>
          </div>
        </div>
      </div>
    </>
  )
}

function BoltOnInstructionsBody() {
  return (
    <>
      <p style={{ fontSize: 12.5, color: 'var(--t2)', marginBottom: 14 }}>
        This domain is bolt-on: no DNS change, your own server enforces the decision.
      </p>
      <div className="dns-row">
        <div className="dns-row-inner">
          <div style={{ flex: 1 }}>
            <div className="dns-label">Call this on every request</div>
            <div className="dns-block" style={{ marginTop: 6 }}>
              <span className="mono">POST /v1/decide</span>
            </div>
            <div className="dns-hint" style={{ marginTop: 6 }}>
              Header: <code>X-Edge-Key: your-key</code> &middot; Body:{' '}
              <code>{'{ "path", "user_agent", "ip" }'}</code>
            </div>
          </div>
        </div>
      </div>
      <div className="dns-row" style={{ borderBottom: 'none' }}>
        <div className="dns-row-inner">
          <div style={{ flex: 1 }}>
            <div className="dns-label">Enforce the response</div>
            <div className="dns-hint" style={{ marginTop: 4 }}>
              <code>allow</code> — serve the real page. <code>block</code> — refuse the request.{' '}
            </div>
          </div>
        </div>
      </div>
      <div className="input-hint" style={{ marginTop: 10 }}>
        The edge key is only shown once, at creation. If it's lost, rotate it with
        <code> POST /api/domains/{'{id}'}/rotate-key</code>; the old key stops working immediately.
      </div>
      <div className="input-hint" style={{ marginTop: 6 }}>
        Copy-paste Node/Express and Nginx snippets live in the repo under <code>integrations/bolt-on/</code>.
      </div>
    </>
  )
}

function VerifyBody({ id, cname, onVerified }) {
  const [status, setStatus] = useState({ text: 'Not yet verified', color: 'var(--t3)' })
  const notify = useToast()
  const { closeModal } = useModal()

  async function check() {
    setStatus({ text: 'Checking…', color: 'var(--t3)' })
    const res = await api.get(`/api/domains/${id}/verify`)
    if (res?.dns_verified) {
      setStatus({ text: 'Verified — your site is now protected.', color: 'var(--green)' })
      notify('DNS verified')
      onVerified()
      setTimeout(closeModal, 1000)
    } else {
      setStatus({ text: 'Not detected yet. Wait a few minutes and try again.', color: 'var(--amber)' })
    }
  }

  return (
    <>
      <p style={{ fontSize: 12.5, color: 'var(--t2)', marginBottom: 14 }}>Add this CNAME record at your DNS provider, then verify.</p>
      <div className="dns-row">
        <div className="dns-row-inner">
          <div className="dns-step-num">1</div>
          <div style={{ flex: 1 }}>
            <div className="dns-label">Add CNAME record</div>
            <div className="dns-hint" style={{ marginBottom: 6 }}>At your registrar (Cloudflare, Namecheap, Route 53…)</div>
            <div className="dns-block">
              <span><span style={{ color: 'var(--t3)' }}>CNAME</span> &nbsp;@ &rarr; <span style={{ color: 'var(--t1)' }}>{cname}</span></span>
              <CopyButton text={cname} />
            </div>
            <div style={{ fontSize: 11, color: 'var(--t3)', marginTop: 6 }}>TTL 300 &middot; Takes 5–30 minutes to propagate</div>
          </div>
        </div>
      </div>
      <div className="dns-row">
        <div className="dns-row-inner">
          <div className="dns-step-num">2</div>
          <div style={{ flex: 1 }}>
            <div className="dns-label">Verify</div>
            <div className="dns-hint">Click below once you've updated your DNS.</div>
            <div style={{ marginTop: 8, fontSize: 12, color: status.color }}>{status.text}</div>
            <button className="btn btn-default" style={{ marginTop: 10 }} onClick={check}>Check DNS</button>
          </div>
        </div>
      </div>
    </>
  )
}

function CopyButton({ text }) {
  const notify = useToast()
  return (
    <button className="copy-btn" onClick={() => { navigator.clipboard.writeText(text); notify('Copied') }}>Copy</button>
  )
}

function AgentMirrorSection({ domain }) {
  const [overrides, setOverrides] = useState(null)
  const notify = useToast()
  const { showModal, closeModal } = useModal()

  const load = async () => {
    const res = await api.get(`/api/mirror/${domain.id}`)
    setOverrides(res?.overrides || [])
  }
  useEffect(() => { load() }, [domain.id])

  function openAddMirrorOverride() {
    showModal('Override a path', <MirrorOverrideBody domain={domain} />, [
      { label: 'Cancel', cls: 'btn-outline', fn: closeModal },
      { label: 'Save', cls: 'btn-default', fn: async () => {
        const path = document.getElementById('mo-path').value.trim()
        const serve_mode = document.getElementById('mo-mode').value
        if (!path.startsWith('/')) return notify('Path must start with /')
        try {
          await api.put(`/api/mirror/${domain.id}`, { path, serve_mode })
          closeModal(); notify(`${path} now serves ${serve_mode}`); load()
        } catch (e) { notify(e.message || 'Failed') }
      }},
    ])
  }

  async function resetOverride(path) {
    try {
      await api.del(`/api/mirror/${domain.id}?path=${encodeURIComponent(path)}`)
      notify(`${path} reset to Agent`); load()
    } catch (e) { notify(e.message || 'Failed') }
  }

  return (
    <div className="sub-section">
      <div className="sub-section-head">
        <div>
          <div className="sub-section-title">Agent Mirror <span className="sub-section-tag">for {domain.domain}</span></div>
          <div className="sub-section-sub">What a paying crawler receives, per page. Default is CrawlBouncer's cleaned agent rendition — override specific paths to send the real page instead.</div>
        </div>
        <button className="btn btn-outline" style={{ fontSize: 11.5 }} onClick={openAddMirrorOverride}>Override a path</button>
      </div>
      {overrides === null ? (
        <div className="empty-sub" style={{ padding: '14px 0' }}>Loading…</div>
      ) : overrides.length ? (
        <div className="tbl-wrap">
          <table>
            <thead><tr><th>Path</th><th>Serves</th><th></th></tr></thead>
            <tbody>
              {overrides.map((o) => (
                <tr key={o.path}>
                  <td className="mono t1">{o.path}</td>
                  <td><span className="badge b-neutral">HTML (real page)</span></td>
                  <td style={{ textAlign: 'right' }}><button className="btn btn-ghost" style={{ fontSize: 11.5 }} onClick={() => resetOverride(o.path)}>Reset to Agent</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-sub" style={{ padding: '10px 0' }}>Every path currently serves the default Agent rendition. No overrides set.</div>
      )}
    </div>
  )
}

function MirrorOverrideBody({ domain }) {
  const [mode, setMode] = useState('html')
  return (
    <>
      <div className="input-group">
        <label className="input-label">Path</label>
        <input className="input mono" id="mo-path" placeholder="/article/my-post" />
        <div className="input-hint">Exact path on {domain.domain}. Everything else keeps the Agent default.</div>
      </div>
      <div className="input-group">
        <label className="input-label">Serve to paying crawlers</label>
        <select className="input" id="mo-mode" value={mode} onChange={(e) => setMode(e.target.value)}>
          <option value="html">Real HTML page (proxied straight to origin)</option>
          <option value="agent">Agent rendition (the default — removes this override)</option>
        </select>
      </div>
    </>
  )
}

function PathRulesSection({ domain }) {
  const [rules, setRules] = useState(null)
  const notify = useToast()
  const { showModal, closeModal } = useModal()

  const load = async () => {
    const res = await api.get(`/api/rules/${domain.id}/paths`)
    setRules(res || [])
  }
  useEffect(() => { load() }, [domain.id])

  function openAddPathRule() {
    showModal('Add a path rule', <PathRuleBody domain={domain} />, [
      { label: 'Cancel', cls: 'btn-outline', fn: closeModal },
      { label: 'Save', cls: 'btn-default', fn: async () => {
        const path_prefix = document.getElementById('pr-path').value.trim()
        const action = document.getElementById('pr-action').value
        if (!path_prefix.startsWith('/')) return notify('Path prefix must start with /')
        try {
          await api.put(`/api/rules/${domain.id}/paths`, { path_prefix, action })
          closeModal(); notify(`${path_prefix} rule saved`); load()
        } catch (e) { notify(e.message || 'Failed') }
      }},
    ])
  }

  async function remove(pathPrefix) {
    try {
      await api.del(`/api/rules/${domain.id}/paths?path_prefix=${encodeURIComponent(pathPrefix)}`)
      notify(`${pathPrefix} rule removed`); load()
    } catch (e) { notify(e.message || 'Failed') }
  }

  return (
    <div className="sub-section">
      <div className="sub-section-head">
        <div>
          <div className="sub-section-title">Path Rules <span className="sub-section-tag">for {domain.domain}</span></div>
          <div className="sub-section-sub">Override the crawler-based rule for a specific path prefix, regardless of which crawler is asking — e.g. always block /premium/, always allow /blog/.</div>
        </div>
        <button className="btn btn-outline" style={{ fontSize: 11.5 }} onClick={openAddPathRule}>Add path rule</button>
      </div>
      {rules === null ? (
        <div className="empty-sub" style={{ padding: '14px 0' }}>Loading…</div>
      ) : rules.length ? (
        <div className="tbl-wrap">
          <table>
            <thead><tr><th>Path prefix</th><th>Action</th><th></th></tr></thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.path_prefix}>
                  <td className="mono t1">{r.path_prefix}</td>
                  <td><ActionBadge action={r.action} /></td>
                  <td style={{ textAlign: 'right' }}><button className="btn btn-ghost" style={{ fontSize: 11.5 }} onClick={() => remove(r.path_prefix)}>Remove</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-sub" style={{ padding: '10px 0' }}>No path rules set. Every path uses the crawler-based rule.</div>
      )}
    </div>
  )
}

function PathRuleBody({ domain }) {
  const [action, setAction] = useState('block')
  return (
    <>
      <div className="input-group">
        <label className="input-label">Path prefix</label>
        <input className="input mono" id="pr-path" placeholder="/premium/" />
        <div className="input-hint">Applies to every path starting with this, for every crawler, on {domain.domain}.</div>
      </div>
      <div className="input-group">
        <label className="input-label">Action</label>
        <select className="input" id="pr-action" value={action} onChange={(e) => setAction(e.target.value)}>
          <option value="block">Block</option>
          <option value="allow">Allow</option>
        </select>
      </div>
    </>
  )
}
