import type { A10ErrorHandlingEvidenceItem } from '../types/api'

export function A10StatusCodePanel({ items }: { items: A10ErrorHandlingEvidenceItem[] }) {
  const rows = items.filter((item) => item.rule_group === 'http_error_patterns' || item.status_code === 500)
  if (!rows.length) return <div className="panel-message">No 5xx status pattern indicators are attached to the selected result.</div>
  return (
    <div className="table-shell">
      <table>
        <thead><tr><th>URL</th><th>Status</th><th>Indicator</th><th>Endpoint Category</th><th>Note</th></tr></thead>
        <tbody>
          {rows.map((item) => (
            <tr key={item.evidence_id || `${item.rule_id}-${item.affected_url}`}>
              <td>{item.affected_url || '-'}</td>
              <td>{item.status_code ?? '-'}</td>
              <td>{item.title || item.rule_id || '-'}</td>
              <td>{item.endpoint_category || '-'}</td>
              <td>{item.safe_evidence_summary || 'Observed status code evidence only. No errors were forced.'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
