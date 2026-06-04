import type { A07AuthenticationEvidenceItem } from '../types/api'
import { A07ConfidenceBadge } from './A07ConfidenceBadge'

export function A07RateLimitIndicatorPanel({ items }: { items: A07AuthenticationEvidenceItem[] }) {
  const rows = items.filter((item) => item.rule_group === 'rate_limit_indicators')
  if (!rows.length) return <div className="panel-message">No rate-limit header indicators available. No rate-limit testing was performed.</div>
  return (
    <div className="table-shell">
      <table>
        <thead><tr><th>Endpoint</th><th>Header Indicator</th><th>Confidence</th><th>Note</th></tr></thead>
        <tbody>
          {rows.map((item) => <tr key={item.evidence_id}><td>{item.affected_url}</td><td>{item.title}</td><td><A07ConfidenceBadge confidence={item.confidence} /></td><td>{item.safe_evidence_summary}</td></tr>)}
        </tbody>
      </table>
    </div>
  )
}
