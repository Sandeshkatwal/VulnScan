import type { OWASPSummary } from '../types/api'

interface OWASPCoverageChartProps {
  summary?: OWASPSummary
}

export function OWASPCoverageChart({ summary }: OWASPCoverageChartProps) {
  const counts = summary?.category_counts || {}
  const max = Math.max(1, ...Object.values(counts).map((value) => Number(value || 0)))
  return (
    <div className="owasp-chart">
      {Object.entries(counts).map(([category, count]) => (
        <div className="owasp-chart__row" key={category}>
          <span>{category}</span>
          <div><strong style={{ width: `${(Number(count || 0) / max) * 100}%` }} /></div>
          <em>{Number(count || 0)}</em>
        </div>
      ))}
    </div>
  )
}
