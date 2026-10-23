import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { fmt } from '../lib/format'
import { useDomain } from '../hooks/useDomain'
import { useToast } from '../components/Toast'

const RULE_CLASS = { allow: 'g', block: 'r' }
const ACTIONS = ['allow', 'block']

export default function Crawlers({ refreshKey }) {
  const { currentDomain } = useDomain()
  const notify = useToast()
  const [crawlerList, setCrawlerList] = useState(null) // from /api/rules/{domain}, the real registry
  const [stats, setStats] = useState({})
  const [rules, setRules] = useState({}) // { name: action } — local edit state
  const [dirty, setDirty] = useState(false)

  useEffect(() => {
    if (!currentDomain) { setCrawlerList([]); return }
    Promise.all([
      api.get(`/api/rules/${currentDomain.id}`),
      api.get('/api/stats/crawlers'),
    ]).then(([registry, statData]) => {
      const list = registry || []
      setCrawlerList(list)
      setStats(Object.fromEntries((statData || []).map((c) => [c.name, c])))

      const initial = {}
      list.forEach((c) => {
        initial[c.crawler_name] = c.action
      })
      setRules(initial)
      setDirty(false)
    })
  }, [refreshKey, currentDomain])

  function setRule(name, action) {
    setRules((prev) => ({ ...prev, [name]: action }))
    setDirty(true)
  }

  async function save() {
    if (!currentDomain) { notify('Add a domain first — rules apply to a specific site'); return }
    const payload = {}
    Object.entries(rules).forEach(([name, action]) => {
      payload[name] = { action }
    })
    try {
      await api.post(`/api/rules/${currentDomain.id}/bulk`, { rules: payload })
      notify('Rules saved')
      setDirty(false)
    } catch (e) {
      notify(e.message || 'Failed to save')
    }
  }

  return (
    <>
      <div className="page-header">
        <div className="page-title">Crawlers</div>
        <div className="page-sub">Allow or block each AI crawler. Changes take effect immediately.</div>
      </div>
      <div className="panel">
        <div className="panel-head">
          <div className="panel-title">AI crawler rules {currentDomain ? <span style={{ fontWeight: 400, color: 'var(--t3)' }}>for {currentDomain.domain}</span> : ''}</div>
          {dirty && <button className="btn btn-default" onClick={save}>Save changes</button>}
        </div>
        {crawlerList === null ? (
          <div className="empty" style={{ padding: 30 }}>Loading…</div>
        ) : !currentDomain ? (
          <div className="empty" style={{ padding: 30 }}>
            <div className="empty-title">Add a domain first</div>
            <div className="empty-sub">Crawler rules apply to a specific site.</div>
          </div>
        ) : (
        <div className="tbl-wrap">
          <table>
            <thead><tr><th>Crawler</th><th>Company</th><th>Requests</th><th>Rule</th></tr></thead>
            <tbody>
              {crawlerList.map((c) => {
                const name = c.crawler_name
                const s = stats[name]
                const current = rules[name] || c.action
                return (
                  <tr key={name}>
                    <td className="t1">{name}{c.robots_only && <span style={{ color: 'var(--t3)', fontSize: 11, marginLeft: 6 }} title="This crawler never shows up as a User-Agent. It is only controlled through robots.txt.">robots.txt only</span>}</td>
                    <td style={{ color: 'var(--t2)' }}>{c.company}</td>
                    <td>{fmt(s?.requests || 0)}</td>
                    <td>
                      <div className="rule-toggle">
                        {ACTIONS.map((action) => (
                          <button
                            key={action}
                            className={`rt-opt${current === action ? ` on ${RULE_CLASS[action]}` : ''}`}
                            onClick={() => setRule(name, action)}
                          >
                            {action[0].toUpperCase() + action.slice(1)}
                          </button>
                        ))}
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
        )}
      </div>
    </>
  )
}
