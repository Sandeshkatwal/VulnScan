import type { SafeValidationSummary } from '../types/api'

interface ValidationSummaryCardsProps {
  summary?: SafeValidationSummary
}

export function ValidationSummaryCards({ summary }: ValidationSummaryCardsProps) {
  const cards = [
    ['Input targets', summary?.input_targets_count || 0],
    ['In scope', summary?.in_scope_targets_count || 0],
    ['Out of scope', summary?.out_of_scope_targets_count || 0],
    ['Checks run', summary?.checks_run || 0],
    ['Indicators', summary?.indicators_found || 0],
    ['Requests', summary?.request_count || 0],
    ['Skipped', summary?.checks_skipped || 0],
  ]
  return (
    <div className="metric-grid metric-grid--compact">
      {cards.map(([label, value]) => (
        <div className="metric-card" key={label}>
          <span>{label}</span>
          <strong>{value}</strong>
        </div>
      ))}
    </div>
  )
}
