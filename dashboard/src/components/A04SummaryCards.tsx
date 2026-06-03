import type { A04CryptoSummary } from '../types/api'

export function A04SummaryCards({ summary }: { summary?: A04CryptoSummary }) {
  const cards = [
    ['Total A04 evidence', summary?.total_evidence_items ?? 0],
    ['Strong indicators', summary?.strong_indicators_count ?? 0],
    ['Weak indicators', summary?.weak_indicators_count ?? 0],
    ['HTTP URLs', summary?.http_urls_count ?? 0],
    ['HTTPS URLs', summary?.https_urls_count ?? 0],
    ['Insecure cookies', summary?.insecure_cookie_count ?? 0],
    ['HSTS issues', summary?.hsts_issue_count ?? 0],
    ['Mixed content', summary?.mixed_content_indicator_count ?? 0],
    ['TLS metadata', summary?.tls_metadata_available ? 'Available' : 'Limited'],
  ]
  return (
    <div className="a04-summary-grid">
      {cards.map(([label, value]) => (
        <div className="summary-card" key={label}>
          <span>{label}</span>
          <strong>{value}</strong>
        </div>
      ))}
    </div>
  )
}
