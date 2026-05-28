import { formatSignedNumber, formatValue } from '../utils/format'
import { TrendStatusBadge } from './TrendStatusBadge'

interface TrendMetricCardProps {
  label: string
  value: unknown
  signed?: boolean
  status?: boolean
}

export function TrendMetricCard({ label, value, signed = false, status = false }: TrendMetricCardProps) {
  return (
    <div className="trend-metric-card">
      <span>{label}</span>
      {status ? <TrendStatusBadge value={value} /> : <strong>{signed ? formatSignedNumber(value) : formatValue(value)}</strong>}
    </div>
  )
}
