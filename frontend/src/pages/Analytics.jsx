import { useEffect, useState } from 'react'
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { api } from '../api/client'
import { fmt } from '../lib/format'
import { ActionBadge } from '../components/Badge'
import { useCountUp } from '../hooks/useCountUp'

export default function Analytics({ refreshKey }) {
  const [traffic, setTraffic] = useState([])
  const [crawlers, setCrawlers] = useState([])
  const [pages, setPages] = useState([])

  useEffect(() => {
    let cancelled = false
    Promise.all([
      api.get('/api/stats/traffic?days=30'),
      api.get('/api/stats/crawlers'),
      api.get('/api/stats/top-pages?limit=8'),
    ]).then(([t, c, p]) => {
      if (cancelled) return
      setTraffic(t || [])
      setCrawlers(c || [])
      setPages(p || [])
    })
    return () => { cancelled = true }
  }, [refreshKey])

  const tot = traffic.reduce((a, b) => a + (b.humans || 0) + (b.bots || 0) + (b.blocked || 0), 0) || 1
  const humans = traffic.reduce((a, b) => a + (b.humans || 0), 0)
  const bots = traffic.reduce((a, b) => a + (b.bots || 0), 0)
  const blocked = traffic.reduce((a, b) => a + (b.blocked || 0), 0)
  const botText = useCountUp(bots, { decimals: 0 })
  const topCrawler = crawlers[0]
  const topSeven = crawlers.slice(0, 7)

  return (
    <>
      <div className="page-header">
        <div className="page-title">Analytics</div>
        <div className="page-sub">Traffic breakdown, crawler activity, and which pages get scraped most.</div>
      </div>

      <div className="grid-3" style={{ marginBottom: 16 }}>
        <div className="panel" style={{ margin: 0 }}>
          <div className="panel-body" style={{ padding: '14px 16px' }}>
            <div className="stat-label" style={{ marginBottom: 6 }}>Total traffic (30d)</div>
            <div className="stat-value" style={{ fontSize: 20 }}>{fmt(tot)}</div>
            <div style={{ marginTop: 10 }}>
              <TrafficBar val={humans} tot={tot} color="var(--t1)" label="Humans" />
              <TrafficBar val={bots} tot={tot} color="var(--t2)" label="AI crawlers" />
              <TrafficBar val={blocked} tot={tot} color="var(--red)" label="Blocked" />
            </div>
          </div>
        </div>
        <div className="panel" style={{ margin: 0 }}>
          <div className="panel-body" style={{ padding: '14px 16px' }}>
            <div className="stat-label" style={{ marginBottom: 6 }}>AI crawler requests (30d)</div>
            <div className="stat-value" style={{ fontSize: 20 }}>{botText}</div>
            <div style={{ height: 50, marginTop: 8 }}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={traffic}>
                  <Line type="monotone" dataKey="bots" stroke="var(--t2)" strokeWidth={1.5} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
        <div className="panel" style={{ margin: 0 }}>
          <div className="panel-body" style={{ padding: '14px 16px' }}>
            <div className="stat-label" style={{ marginBottom: 6 }}>Top crawler</div>
            {topCrawler ? (
              <>
                <div className="stat-value" style={{ fontSize: 16 }}>{topCrawler.name}</div>
                <div style={{ color: 'var(--t2)', fontSize: 12, marginTop: 4 }}>{topCrawler.company} &middot; {fmt(topCrawler.requests)} requests</div>
                <div style={{ marginTop: 8 }}><ActionBadge action={topCrawler.action} /></div>
              </>
            ) : <div className="stat-value" style={{ fontSize: 16 }}>—</div>}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head"><div><div className="panel-title">Crawler comparison</div><div className="panel-sub">Requests by AI company</div></div></div>
        <div className="panel-body">
          <div className="chart-box">
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={topSeven} layout="vertical">
                <XAxis type="number" tick={{ fontSize: 11, fill: 'var(--t3)' }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: 'var(--t2)' }} axisLine={false} tickLine={false} width={90} />
                <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', fontSize: 12 }} />
                <Bar dataKey="requests" fill="var(--t1)" radius={[0, 2, 2, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid-2">
        <div className="panel">
          <div className="panel-head"><div className="panel-title">AI crawler requests over time</div></div>
          <div className="panel-body">
            <div className="chart-box">
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={traffic}>
                  <XAxis dataKey="date" tick={{ fontSize: 11, fill: 'var(--t3)' }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', fontSize: 12 }} />
                  <Line type="monotone" dataKey="bots" name="AI crawlers" stroke="var(--t2)" strokeWidth={1.5} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
        <div className="panel">
          <div className="panel-head"><div className="panel-title">Top pages scraped</div></div>
          <div className="tbl-wrap">
            <table>
              <thead><tr><th>Path</th><th style={{ textAlign: 'right' }}>Bot visits</th></tr></thead>
              <tbody>
                {pages.length ? pages.map((p, i) => (
                  <tr key={i}>
                    <td className="mono t1" style={{ maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.path}</td>
                    <td className="right">{fmt(p.bot_visits || 0)}</td>
                  </tr>
                )) : <tr><td colSpan={2}><div className="empty"><div className="empty-title">No data</div></div></td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  )
}

function TrafficBar({ val, tot, color, label }) {
  const pct = ((val / tot) * 100).toFixed(1)
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5, color: 'var(--t2)', marginBottom: 4 }}>
        <span>{label}</span>
        <span className="mono">{fmt(val)} <span style={{ color: 'var(--t3)' }}>{pct}%</span></span>
      </div>
      <div style={{ height: 3, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 2 }} />
      </div>
    </div>
  )
}
