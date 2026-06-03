import type { A04CryptoEvidenceItem } from '../types/api'
import { A04ConfidenceBadge } from './A04ConfidenceBadge'

export function A04MixedContentPanel({ items }: { items: A04CryptoEvidenceItem[] }) {
  const rows = items.filter((item) => item.rule_group === 'mixed_content_indicators')
  if (!rows.length) return <div className="panel-message">No mixed content indicators available.</div>
  return (
    <div className="table-shell">
      <table>
        <thead><tr><th>URL</th><th>Resource Type</th><th>Resource Scheme</th><th>Confidence</th><th>Manual Validation Note</th></tr></thead>
        <tbody>
          {rows.map((item) => (
            <tr key={item.evidence_id}>
              <td>{item.affected_url}</td>
              <td>{item.resource_type}</td>
              <td>{item.resource_scheme}</td>
              <td><A04ConfidenceBadge confidence={item.confidence} /></td>
              <td>{item.manual_validation_required ? 'Manual validation required' : 'Evidence metadata only'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
