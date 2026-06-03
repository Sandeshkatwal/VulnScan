import type { A04CryptoEvidenceItem } from '../types/api'
import { A04ConfidenceBadge } from './A04ConfidenceBadge'

export function A04CookieEvidenceTable({ items }: { items: A04CryptoEvidenceItem[] }) {
  const rows = items.filter((item) => item.rule_group === 'cookie_security')
  if (!rows.length) return <div className="panel-message">No cookie security evidence available.</div>
  return (
    <div className="table-shell">
      <table>
        <thead><tr><th>URL</th><th>Cookie Name</th><th>Missing Attributes</th><th>Confidence</th><th>Recommendation</th></tr></thead>
        <tbody>
          {rows.map((item) => (
            <tr key={item.evidence_id}>
              <td>{item.affected_url}</td>
              <td>{item.cookie_name}</td>
              <td>{item.missing_attributes?.join(', ') || 'Contextual review'}</td>
              <td><A04ConfidenceBadge confidence={item.confidence} /></td>
              <td>{item.recommendation}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
