/** Direct port of dashboard.html's sparkline() helper. */
export default function Sparkline({ data, color }) {
  if (!data || !data.length) return null
  const w = 80, h = 28
  const min = Math.min(...data), max = Math.max(...data), r = max - min || 1
  const points = data
    .map((v, i) => `${(i / (data.length - 1 || 1)) * w},${h - ((v - min) / r) * (h - 4) - 2}`)
    .join(' ')
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} style={{ display: 'block' }}>
      <polyline points={points} fill="none" stroke={color} strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
