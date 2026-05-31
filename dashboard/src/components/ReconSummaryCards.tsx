import type { BugBountyReconSummary } from '../types/api'

interface ReconSummaryCardsProps {
  summary?: BugBountyReconSummary | null
}

function value(input: unknown): string {
  return input === undefined || input === null || input === '' ? '0' : String(input)
}

export function ReconSummaryCards({ summary }: ReconSummaryCardsProps) {
  const cards = [
    ['Input', summary?.input_targets_count],
    ['In Scope', summary?.in_scope_targets_count],
    ['Out of Scope', summary?.out_of_scope_targets_count],
    ['Live', summary?.live_count],
    ['Errors', summary?.error_count],
    ['Skipped', summary?.skipped_count],
  ]

  return (
    <div className="recon-summary-grid">
      {cards.map(([label, cardValue]) => (
        <div className="stat-card" key={String(label)}>
          <span>{label}</span>
          <strong>{value(cardValue)}</strong>
        </div>
      ))}
    </div>
  )
}
