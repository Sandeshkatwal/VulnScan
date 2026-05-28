import type { ApiRecord } from '../types/api'
import { formatValue } from '../utils/format'

interface TrendSummaryCardProps {
  trends?: ApiRecord | null
  dashboard?: ApiRecord | null
}

function firstAvailable(...values: unknown[]): unknown {
  return values.find((value) => value !== undefined && value !== null && value !== '')
}

export function TrendSummaryCard({ trends, dashboard }: TrendSummaryCardProps) {
  const source = trends && Object.keys(trends).length ? trends : dashboard
  const enabled = source?.enabled !== false && source?.risk_trend_label

  if (!source || !enabled) {
    return <div className="context-card__message">Trend data is available when scans are run with --priority-trends and --save-db.</div>
  }

  const rows: Array<[string, unknown]> = [
    ['Risk trend', source.risk_trend_label],
    ['New findings', source.new_findings_count],
    ['Resolved findings', source.resolved_findings_count],
    ['New Fix First', firstAvailable(source.fix_first_new_count, source.new_fix_first_count)],
    ['Resolved Fix First', firstAvailable(source.fix_first_resolved_count, source.resolved_fix_first_count)],
    ['Average priority delta', source.average_priority_delta],
  ]

  return (
    <dl className="context-card__grid">
      {rows.map(([label, value]) => (
        <div key={String(label)}>
          <dt>{String(label)}</dt>
          <dd>{formatValue(value)}</dd>
        </div>
      ))}
    </dl>
  )
}
