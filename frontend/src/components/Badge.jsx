import { actionBadgeClass, actionBadgeLabel } from '../lib/format'

export function ActionBadge({ action }) {
  return <span className={`badge ${actionBadgeClass(action)}`}>{actionBadgeLabel(action)}</span>
}

export function StatusBadge({ ok, yes = 'Verified', no = 'Pending' }) {
  return <span className={`badge ${ok ? 'b-green' : 'b-neutral'}`}>{ok ? yes : no}</span>
}

export function ModeBadge({ mode }) {
  return mode === 'bolt_on'
    ? <span className="badge b-blue">Bolt-on</span>
    : <span className="badge b-neutral">Reverse proxy</span>
}

const SEVERITY = { critical: ['b-red', 'Critical'], high: ['b-amber', 'High'], medium: ['b-blue', 'Medium'], low: ['b-neutral', 'Low'] }

export function SeverityBadge({ severity }) {
  const [cls, label] = SEVERITY[severity] || ['b-neutral', severity]
  return <span className={`badge ${cls}`}>{label}</span>
}
