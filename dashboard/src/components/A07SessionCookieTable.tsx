import type { A07AuthenticationEvidenceItem } from '../types/api'
import { A07ConfidenceBadge } from './A07ConfidenceBadge'

export function A07SessionCookieTable({ items }: { items: A07AuthenticationEvidenceItem[] }) {
  const rows = items.filter((item) => item.rule_group === 'session_cookie_indicators')
  if (!rows.length) return <div className="panel-message">No cookie/session evidence available.</div>
  return (
    <div className="table-shell">
      <table>
        <thead><tr><th>URL</th><th>Cookie Name</th><th>Missing Attributes</th><th>Persistence Indicator</th><th>Confidence</th><th>Recommendation</th></tr></thead>
        <tbody>
          {rows.map((item) => (
            <tr key={item.evidence_id}>
              <td>{item.affected_url}</td>
              <td>{item.cookie_name}</td>
              <td>{item.missing_attributes?.join(', ') || 'Contextual review'}</td>
              <td>{String(item.persistence_indicator ?? false)}</td>
              <td><A07ConfidenceBadge confidence={item.confidence} /></td>
              <td>{item.recommendation}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
