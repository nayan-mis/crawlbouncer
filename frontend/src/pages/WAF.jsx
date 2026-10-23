import { useEffect, useMemo, useState } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { api } from '../api/client'
import { fmt } from '../lib/format'
import { SeverityBadge } from '../components/Badge'
import { useCountUp } from '../hooks/useCountUp'

const WAF_RULES = [
  { id: 'SQLi-001', name: 'SQL Union Attack', cat: 'SQL Injection', sev: 'critical', act: 'block' },
  { id: 'SQLi-002', name: 'Boolean Injection', cat: 'SQL Injection', sev: 'critical', act: 'block' },
  { id: 'SQLi-003', name: 'Destructive SQL', cat: 'SQL Injection', sev: 'critical', act: 'block' },
  { id: 'SQLi-004', name: 'Time-Based Blind', cat: 'SQL Injection', sev: 'high', act: 'block' },
  { id: 'SQLi-005', name: 'Error-Based Injection', cat: 'SQL Injection', sev: 'high', act: 'block' },
  { id: 'XSS-001', name: 'Script Tag', cat: 'XSS', sev: 'high', act: 'block' },
  { id: 'XSS-002', name: 'JavaScript Protocol', cat: 'XSS', sev: 'high', act: 'block' },
  { id: 'XSS-003', name: 'Event Handler', cat: 'XSS', sev: 'high', act: 'block' },
  { id: 'XSS-004', name: 'Entity Bypass', cat: 'XSS', sev: 'medium', act: 'block' },
  { id: 'PT-001', name: 'Path Traversal', cat: 'Path Traversal', sev: 'high', act: 'block' },
  { id: 'PT-002', name: 'Sensitive File', cat: 'Path Traversal', sev: 'critical', act: 'block' },
  { id: 'CMDi-001', name: 'Shell Metacharacters', cat: 'Command Injection', sev: 'critical', act: 'block' },
  { id: 'CMDi-002', name: 'Command Substitution', cat: 'Command Injection', sev: 'high', act: 'block' },
  { id: 'BAC-001', name: 'Admin Path', cat: 'Access Control', sev: 'medium', act: 'log' },
  { id: 'BAC-002', name: 'IDOR Pattern', cat: 'Access Control', sev: 'medium', act: 'log' },
  { id: 'SSRF-001', name: 'Internal IP', cat: 'SSRF', sev: 'critical', act: 'block' },
  { id: 'SSRF-002', name: 'AWS Metadata', cat: 'SSRF', sev: 'critical', act: 'block' },
  { id: 'XXE-001', name: 'XML External Entity', cat: 'XXE', sev: 'high', act: 'block' },
  { id: 'NULL-001', name: 'Null Byte', cat: 'Injection', sev: 'medium', act: 'block' },
  { id: 'SEC-001', name: 'Sensitive Files', cat: 'Misconfiguration', sev: 'high', act: 'block' },
]

export default function WAF({ refreshKey }) {
  const [stats, setStats] = useState({})
  const [filter, setFilter] = useState('')
  const blockedText = useCountUp(stats.total_blocked || 0)

  useEffect(() => { api.get('/api/stats/waf').then((data) => setStats(data || {})) }, [refreshKey])

  const catCounts = useMemo(() => {
    const cats = [...new Set(WAF_RULES.map((r) => r.cat))]
    return cats.map((cat) => ({ cat, count: WAF_RULES.filter((r) => r.cat === cat).length }))
  }, [])

  const filteredRules = WAF_RULES.filter((r) =>
    `${r.id} ${r.name} ${r.cat}`.toLowerCase().includes(filter.toLowerCase())
  )

  return (
    <>
      <div className="page-header">
        <div className="page-title">WAF</div>
        <div className="page-sub">20 OWASP rules active. Every request inspected before reaching your origin.</div>
      </div>

      <div className="stat-row" style={{ gridTemplateColumns: 'repeat(3,1fr)' }}>
        <div className="stat-card"><div className="stat-label">Requests blocked</div><div className="stat-value">{blockedText}</div><div className="stat-sub">All time</div></div>
        <div className="stat-card"><div className="stat-label">Active rules</div><div className="stat-value">20</div><div className="stat-sub">OWASP CRS</div></div>
        <div className="stat-card"><div className="stat-label">Status</div><div className="stat-value" style={{ color: 'var(--green)' }}>Active</div><div className="stat-sub">All domains</div></div>
      </div>

      <div className="grid-2">
        <div className="panel">
          <div className="panel-head"><div className="panel-title">Rule categories</div></div>
          <div className="panel-body">
            <div className="chart-box">
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={catCounts} layout="vertical">
                  <XAxis type="number" allowDecimals={false} tick={{ fontSize: 11, fill: 'var(--t3)' }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="cat" tick={{ fontSize: 11, fill: 'var(--t2)' }} axisLine={false} tickLine={false} width={120} />
                  <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', fontSize: 12 }} />
                  <Bar dataKey="count" fill="var(--t1)" radius={[0, 2, 2, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
        <div className="panel">
          <div className="panel-head"><div className="panel-title">Recent blocks</div></div>
          <div className="tbl-wrap">
            <table>
              <thead><tr><th>Rule</th><th>Severity</th><th style={{ textAlign: 'right' }}>Blocks</th></tr></thead>
              <tbody>
                {(stats.by_rule || []).length ? stats.by_rule.map((r, i) => (
                  <tr key={i}><td className="t1">{r.rule_name}</td><td><SeverityBadge severity={r.severity} /></td><td className="right">{r.count}</td></tr>
                )) : (
                  <tr><td colSpan={3}><div className="empty"><div className="empty-title">No blocks yet</div><div className="empty-sub">WAF is active and watching.</div></div></td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <div className="panel-title">All 20 rules</div>
          <div className="panel-controls">
            <input className="search-input" placeholder="Filter rules…" value={filter} onChange={(e) => setFilter(e.target.value)} />
          </div>
        </div>
        <div className="tbl-wrap">
          <table>
            <thead><tr><th>ID</th><th>Rule</th><th>Category</th><th>Severity</th><th>Action</th></tr></thead>
            <tbody>
              {filteredRules.map((r) => (
                <tr key={r.id}>
                  <td className="mono" style={{ color: 'var(--t3)' }}>{r.id}</td>
                  <td className="t1">{r.name}</td>
                  <td style={{ color: 'var(--t2)' }}>{r.cat}</td>
                  <td><SeverityBadge severity={r.sev} /></td>
                  <td>{r.act === 'block' ? <span className="badge b-red">Block</span> : <span className="badge b-neutral">Log</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}
