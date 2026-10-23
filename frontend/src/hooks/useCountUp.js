import { useEffect, useState } from 'react'

/**
 * Direct port of dashboard.html's countUp(el, end, prefix, suffix, decimals)
 * — same duration (700ms) and step (16ms), re-animates from 0 whenever
 * `end` changes (e.g. new data loaded). Returns the already-formatted
 * string so callers can drop it straight into JSX.
 */
export function useCountUp(end, { prefix = '', suffix = '', decimals = 0 } = {}) {
  const [text, setText] = useState(() => format(0, prefix, suffix, decimals))

  useEffect(() => {
    const target = end || 0
    const dur = 700
    const step = 16
    const steps = dur / step
    let cur = 0

    const timer = setInterval(() => {
      cur++
      const v = Math.min(target * (cur / steps), target)
      setText(format(v, prefix, suffix, decimals))
      if (cur >= steps) clearInterval(timer)
    }, step)

    return () => clearInterval(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [end])

  return text
}

function format(v, prefix, suffix, decimals) {
  return prefix + (decimals ? v.toFixed(decimals) : Math.floor(v).toLocaleString()) + suffix
}
