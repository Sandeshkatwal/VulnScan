import type { A07AuthenticationEvidenceItem } from '../types/api'
import { A07ConfidenceBadge } from './A07ConfidenceBadge'

export function A07AuthEndpointTable({ items }: { items: A07AuthenticationEvidenceItem[] }) {
  const rows = items.filter((item) => item.rule_group === 'auth_endpoint_discovery')
  if (!rows.length) return <div className="panel-message">No authentication endpoint indicators available.</div>
  return (
    <div className="table-shell">
      <table>
        <thead><tr><th>URL</th><th>Endpoint Type</th><th>Confidence</th><th>Manual Validation Note</th></tr></thead>
        <tbody>
          {rows.map((item) => <tr key={item.evidence_id}><td>{item.affected_url}</td><td>{item.endpoint_type}</td><td><A07ConfidenceBadge confidence={item.confidence} /></td><td>{item.manual_validation_required ? 'Manual validation required' : 'Evidence metadata only'}</td></tr>)}
        </tbody>
      </table>
    </div>
  )
}
