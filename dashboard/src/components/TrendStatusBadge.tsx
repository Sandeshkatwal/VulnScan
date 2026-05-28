import { normaliseTrendLabel } from '../utils/trendMetrics'

interface TrendStatusBadgeProps {
  value?: unknown
}

export function TrendStatusBadge({ value }: TrendStatusBadgeProps) {
  const label = normaliseTrendLabel(value)
  return <span className={`trend-status-badge trend-status-badge--${label.toLowerCase()}`}>{label}</span>
}
