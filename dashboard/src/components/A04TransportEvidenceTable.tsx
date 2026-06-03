import type { A04CryptoEvidenceItem } from '../types/api'
import { A04ConfidenceBadge } from './A04ConfidenceBadge'

export function A04TransportEvidenceTable({ items }: { items: A04CryptoEvidenceItem[] }) {
  const rows = items.filter((item) => ['transport_security', 'cleartext_sensitive_workflows', 'hsts'].includes(String(item.rule_group)))
  if (!rows.length) return <div className="panel-message">No transport security indicators available.</div>
  return (
    <div className="table-shell">
      <table>
        <thead><tr><th>URL</th><th>Scheme</th><th>Issue</th><th>Confidence</th><th>Evidence Strength</th><th>Recommendation</th></tr></thead>
        <tbody>
          {rows.map((item) => (
            <tr key={item.evidence_id}>
              <td>{item.affected_url}</td>
              <td>{item.scheme}</td>
              <td>{item.title}</td>
              <td><A04ConfidenceBadge confidence={item.confidence} /></td>
              <td>{item.evidence_strength}</td>
              <td>{item.recommendation}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
