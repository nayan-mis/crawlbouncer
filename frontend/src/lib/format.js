export function fmt(n) {
  return (n || 0).toLocaleString()
}

export function actionBadgeClass(action) {
  return { block: 'b-red', allow: 'b-green' }[action] || 'b-neutral'
}

export function actionBadgeLabel(action) {
  return { block: 'Block', allow: 'Allow' }[action] || action || '—'
}
