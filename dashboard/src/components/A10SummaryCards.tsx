import type { A10ErrorHandlingSummary } from '../types/api'

const cards = [
  ['total_evidence_items', 'Total A10 Evidence'],
  ['strong_indicators_count', 'Strong Indicators'],
  ['weak_indicators_count', 'Weak Indicators'],
  ['stack_trace_count', 'Stack Traces'],
  ['database_error_count', 'Database Errors'],
  ['framework_error_count', 'Framework Debug Indicators'],
  ['status_5xx_count', '5xx Observations'],
  ['manual_validation_required_count', 'Manual Validation Required'],
] as const

export function A10SummaryCards({ summary }: { summary?: A10ErrorHandlingSummary }) {
  return (
    <div className="a10-summary-grid">
      {cards.map(([key, label]) => (
        <div className="summary-card" key={key}>
          <span>{label}</span>
          <strong>{Number(summary?.[key] || 0)}</strong>
        </div>
      ))}
    </div>
  )
}
