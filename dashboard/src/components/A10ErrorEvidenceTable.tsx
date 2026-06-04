import type { A10ErrorHandlingEvidenceItem } from '../types/api'
import { A10ConfidenceBadge } from './A10ConfidenceBadge'

export function A10ErrorEvidenceTable({ items }: { items: A10ErrorHandlingEvidenceItem[] }) {
  const rows = items.filter((item) => item.rule_group !== 'fail_open_manual_review')
  if (!rows.length) return <div className="panel-message">No verbose error evidence is attached to the selected result.</div>
  return (
    <div className="table-shell">
      <table>
        <thead>
          <tr>
            <th>URL</th>
            <th>Status</th>
            <th>Pattern</th>
            <th>Evidence Strength</th>
            <th>Confidence</th>
            <th>Redacted Snippet</th>
            <th>Recommendation</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((item) => (
            <tr key={item.evidence_id || `${item.rule_id}-${item.affected_url}`}>
              <td>{item.affected_url || '-'}</td>
              <td>{item.status_code ?? '-'}</td>
              <td>{item.observed_pattern || item.title || item.rule_id || '-'}</td>
              <td>{item.evidence_strength || '-'}</td>
              <td><A10ConfidenceBadge confidence={item.confidence} /></td>
              <td className="snippet-cell">{item.redacted_snippet || item.safe_evidence_summary || '-'}</td>
              <td>{item.recommendation || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
