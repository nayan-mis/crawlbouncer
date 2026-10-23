import { useEffect, useState } from 'react'
import { LineChart, Line, XAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import { api } from '../api/client'
import { fmt } from '../lib/format'
import { ActionBadge } from '../components/Badge'
import Sparkline from '../components/Sparkline'
import { useCountUp } from '../hooks/useCountUp'

const RANGES = [7, 14, 30]

export default function Overview({ refreshKey }) {
  const [ov, setOv] = useState(null)
  const [traffic, setTraffic] = useState([])
  const [crawlers, setCrawlers] = useState([])
  const [feed, setFeed] = useState([])
  const [days, setDays] = useState(7)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    Promise.all([
      api.get('/api/stats/overview'),
      api.get(`/api/stats/traffic?days=${days}`),
      api.get('/api/stats/crawlers'),
      api.get('/api/requests/log?limit=12'),
    ]).then(([overview, trafficData, crawlerData, feedData]) => {
      if (cancelled) return
      setOv(overview)
      setTraffic(trafficData || [])
      setCrawlers(crawlerData || [])
      setFeed(feedData?.requests || [])
      setLoading(false)
    })
    return () => { cancelled = true }
  }, [refreshKey, days])

  const donutData = ov ? [
    { name: 'Humans', value: ov.human_requests || 0, color: 'var(--t1)' },
    { name: 'AI crawlers', value: ov.bot_requests || 0, color: 'var(--t2)' },
    { name: 'Blocked', value: ov.blocked || 0, color: 'var(--red)' },
  ] : []
  const donutTotal = donutData.reduce((s, d) => s + d.value, 0) || 1

  const hSpark = traffic.map((r) => r.humans || 0).slice(-14)
  const bSpark = traffic.map((r) => r.bots || 0).slice(-14)
  const blSpark = traffic.map((r) => r.blocked || 0).slice(-14)

  return (
    <>
      <div className="page-header">
        <div className="page-title">Dashboard</div>
        <div className="page-sub">Who is visiting your domains, and what the bouncer did about it.</div>
      </div>

      <div className="stat-row">
        <StatCard label="Total requests" value={ov?.total_requests} sub={ov ? `${fmt(ov.human_requests)} human, ${fmt(ov.bot_requests)} bots` : '—'} spark={hSpark} sparkColor="var(--t3)" />
        <StatCard label="Crawlers allowed" value={ov?.crawlers_allowed} sub="AI crawler requests let through" />
        <StatCard label="AI crawlers" value={ov ? Number((ov.bot_percentage || 0).toFixed(1)) : 0} suffix="%" decimals={1} sub="Of total traffic" spark={bSpark} sparkColor="var(--t3)" />
        <StatCard label="Blocked" value={ov?.blocked} valueColor="var(--red)" sub="Requests refused this month" spark={blSpark} sparkColor="var(--red)" />
      </div>

      <div className="panel">
        <div className="panel-head">
          <div>
            <div className="panel-title">Traffic</div>
            <div className="panel-sub">Requests over time by type</div>
          </div>
          <div className="pill-tabs">
            {RANGES.map((d) => (
              <button key={d} className={`pill-tab${days === d ? ' on' : ''}`} onClick={() => setDays(d)}>{d}d</button>
            ))}
          </div>
        </div>
        <div className="panel-body">
          <div className="chart-lg">
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={traffic}>
                <XAxis dataKey="date" tick={{ fontSize: 11, fill: 'var(--t3)' }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', fontSize: 12 }} />
                <Line type="monotone" dataKey="humans" name="Humans" stroke="var(--t1)" strokeWidth={1.5} dot={false} />
                <Line type="monotone" dataKey="bots" name="AI crawlers" stroke="var(--t2)" strokeWidth={1.5} strokeDasharray="4 2" dot={false} />
                <Line type="monotone" dataKey="blocked" name="Blocked" stroke="var(--red)" strokeWidth={1.5} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div style={{ display: 'flex', gap: 16, marginTop: 10, flexWrap: 'wrap' }}>
            <Legend color="var(--t1)" label="Humans" />
            <Legend color="var(--t2)" label="AI crawlers" />
            <Legend color="var(--red)" label="Blocked" />
          </div>
        </div>
      </div>

      <div className="grid-62">
        <div className="panel">
          <div className="panel-head">
            <div className="panel-title">AI crawlers</div>
            <div className="panel-sub">Requests this month</div>
          </div>
          <div className="tbl-wrap">
            <table>
              <thead><tr><th>Crawler</th><th>Company</th><th style={{ textAlign: 'right' }}>Requests</th><th>Rule</th></tr></thead>
              <tbody>
                {crawlers.length ? crawlers.slice(0, 8).map((c) => (
                  <tr key={c.name}>
                    <td className="t1">{c.name}</td>
                    <td>{c.company || '—'}</td>
                    <td className="right">{fmt(c.requests)}</td>
                    <td><ActionBadge action={c.action} /></td>
                  </tr>
                )) : (
                  <tr><td colSpan={4}><div className="empty"><div className="empty-title">No crawler data yet</div></div></td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
        <div>
          <div className="panel" style={{ marginBottom: 12 }}>
            <div className="panel-head"><div className="panel-title">Traffic split</div></div>
            <div className="panel-body">
              <div style={{ height: 140 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={donutData} dataKey="value" innerRadius={45} outerRadius={65}>
                      {donutData.map((d, i) => <Cell key={i} fill={d.color} />)}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 12 }}>
                {donutData.map((d) => (
                  <div key={d.name} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 11.5 }}>
                    <Legend color={d.color} label={d.name} />
                    <span className="mono" style={{ color: 'var(--t2)' }}>{fmt(d.value)} <span style={{ color: 'var(--t3)' }}>({((d.value / donutTotal) * 100).toFixed(0)}%)</span></span>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <div className="panel">
            <div className="panel-head"><div className="panel-title">Request feed</div></div>
            <div style={{ maxHeight: 180, overflowY: 'auto' }}>
              {feed.length ? feed.map((r, i) => {
                const color = r.is_bot ? (r.action === 'block' ? 'var(--red)' : 'var(--t2)') : 'var(--green)'
                const label = r.crawler_name || (r.is_bot ? 'Bot' : 'Human')
                return (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 14px', borderBottom: '1px solid var(--border)', fontSize: 11.5 }}>
                    <div style={{ width: 5, height: 5, borderRadius: '50%', background: color, flexShrink: 0 }} />
                    <span className="mono" style={{ color: 'var(--t3)', minWidth: 46 }}>{(r.timestamp || '').slice(11, 19)}</span>
                    <span style={{ flex: 1, color: 'var(--t2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.path}</span>
                    <span style={{ color: 'var(--t3)' }}>{label}</span>
                  </div>
                )
              }) : <div className="empty"><div className="empty-title">No requests yet</div></div>}
            </div>
          </div>
        </div>
      </div>
    </>
  )
}

function StatCard({ label, value, prefix = '', suffix = '', decimals = 0, sub, valueColor, spark, sparkColor }) {
  const text = useCountUp(value, { prefix, suffix, decimals })
  return (
    <div className="stat-card">
      <div className="stat-top"><div className="stat-label">{label}</div></div>
      <div className="stat-value" style={valueColor ? { color: valueColor } : undefined}>{text}</div>
      <div className="stat-sub">{sub}</div>
      {spark && spark.length > 1 && <div className="stat-sparkline"><Sparkline data={spark} color={sparkColor} /></div>}
    </div>
  )
}

function Legend({ color, label }) {
  return (
    <div className="legend-item">
      <div className="legend-dot" style={{ background: color }} />
      {label}
    </div>
  )
}
