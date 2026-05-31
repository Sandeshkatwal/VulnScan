import type { EndpointDiscoverySummary } from '../types/api'

interface EndpointSummaryCardsProps {
  summary?: EndpointDiscoverySummary
}

const cards: Array<{ label: string; key: keyof EndpointDiscoverySummary }> = [
  { label: 'Input URLs', key: 'input_urls_count' },
  { label: 'In Scope', key: 'in_scope_urls_count' },
  { label: 'Out of Scope', key: 'out_of_scope_urls_count' },
  { label: 'With Parameters', key: 'endpoints_with_parameters_count' },
  { label: 'Interesting Parameters', key: 'interesting_parameters_count' },
  { label: 'High Interest', key: 'high_interest_count' },
  { label: 'Medium Interest', key: 'medium_interest_count' },
]

export function EndpointSummaryCards({ summary }: EndpointSummaryCardsProps) {
  return (
    <div className="metric-grid metric-grid--compact">
      {cards.map((card) => (
        <div className="metric-card" key={card.key}>
          <span>{card.label}</span>
          <strong>{Number(summary?.[card.key] || 0)}</strong>
        </div>
      ))}
    </div>
  )
}
