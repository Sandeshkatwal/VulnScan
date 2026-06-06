import type { A05InjectionSummary } from '../types/api'

export function A05SummaryCards({ summary }: { summary: A05InjectionSummary }) {
  const cards = [
    ['Total A05 evidence', summary.total_evidence_items],
    ['Strong indicators', summary.strong_indicators_count],
    ['Weak indicators', summary.weak_indicators_count],
    ['Parameter candidates', summary.parameter_candidate_count],
    ['Form input candidates', summary.form_input_candidate_count],
    ['API input candidates', summary.api_input_candidate_count],
    ['Reflections observed', summary.reflection_observed_count],
    ['Manual validation', summary.manual_validation_required_count],
  ]
  return (
    <div className="a05-summary-grid">
      {cards.map(([label, value]) => (
        <div className="metric-card" key={label}>
          <span>{label}</span>
          <strong>{Number(value || 0)}</strong>
        </div>
      ))}
    </div>
  )
}
