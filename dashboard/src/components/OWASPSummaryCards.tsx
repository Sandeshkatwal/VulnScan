import type { OWASPSummary } from '../types/api'

interface OWASPSummaryCardsProps {
  summary?: OWASPSummary
}

export function OWASPSummaryCards({ summary }: OWASPSummaryCardsProps) {
  const highest = summary?.highest_signal_categories?.[0]
  const cards = [
    ['Mapped findings', summary?.mapped_findings_count || 0],
    ['Unmapped findings', summary?.unmapped_findings_count || 0],
    ['Manual validation', summary?.manual_validation_required_count || 0],
    ['Highest signal', highest ? `${highest.owasp_id} (${highest.count})` : 'None'],
    ['Coverage gaps', summary?.coverage_gaps?.length || 0],
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
