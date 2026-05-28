import { formatValue } from '../utils/format'

interface RiskMetricCardProps {
  label: string
  value: unknown
  description?: string
}

export function RiskMetricCard({ label, value, description }: RiskMetricCardProps) {
  return (
    <div className="risk-metric-card">
      <span>{label}</span>
      <strong>{formatValue(value)}</strong>
      {description ? <small>{description}</small> : null}
    </div>
  )
}
