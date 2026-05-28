import type { ApiRecord, PrioritisationTrends } from '../types/api'
import { formatDateTime, formatSignedNumber, formatValue } from '../utils/format'
import { trendValue } from '../utils/trendMetrics'

interface TrendComparisonPanelProps {
  trends: PrioritisationTrends | null
  dashboard: ApiRecord
}

export function TrendComparisonPanel({ trends, dashboard }: TrendComparisonPanelProps) {
  const status = String(trends?.status || '').toLowerCase()
  const previousScanId = trends?.previous_scan_id

  if (status === 'baseline' || !previousScanId) {
    return <div className="context-card__message">This scan is the trend baseline.</div>
  }

  const rows: Array<[string, unknown, 'date' | 'delta' | 'value']> = [
    ['Previous scan time', trends?.previous_scan_time, 'date'],
    ['Current scan time', trends?.current_scan_time, 'date'],
    ['Previous findings count', trends?.previous_findings_count, 'value'],
    ['Current findings count', trends?.current_findings_count, 'value'],
    ['Previous average priority', trends?.previous_average_priority_score, 'value'],
    ['Current average priority', trends?.current_average_priority_score, 'value'],
    ['Average delta', trendValue(trends, dashboard, 'average_priority_delta'), 'delta'],
    ['Previous highest priority', trends?.previous_highest_priority_score, 'value'],
    ['Current highest priority', trends?.current_highest_priority_score, 'value'],
    ['Highest delta', trendValue(trends, dashboard, 'highest_priority_delta'), 'delta'],
  ]

  return (
    <dl className="trend-comparison-grid">
      {rows.map(([label, value, mode]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd>{mode === 'date' ? formatDateTime(value) : mode === 'delta' ? formatSignedNumber(value) : formatValue(value)}</dd>
        </div>
      ))}
    </dl>
  )
}
