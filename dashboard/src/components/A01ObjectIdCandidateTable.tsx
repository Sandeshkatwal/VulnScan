import type { A01AccessControlEvidenceItem } from '../types/api'
import { A01ConfidenceBadge } from './A01ConfidenceBadge'

export function A01ObjectIdCandidateTable({ items }: { items: A01AccessControlEvidenceItem[] }) {
  const rows = items.filter((item) => item.rule_group === 'object_level_authorization_candidates')
  if (!rows.length) return <div className="panel-message">No object-level authorization candidates are attached to this result.</div>
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Endpoint/path</th><th>Parameter</th><th>Object type hint</th><th>Score</th><th>Confidence</th><th>Manual validation</th></tr></thead>
        <tbody>
          {rows.map((item) => (
            <tr key={item.evidence_id}>
              <td>{item.affected_url || 'normalised path unavailable'}</td>
              <td>{item.affected_parameter || 'path identifier'}</td>
              <td>{item.object_type_hint || 'object'}</td>
              <td>{item.candidate_score || 0}</td>
              <td><A01ConfidenceBadge confidence={item.confidence} /></td>
              <td>{item.manual_validation_required ? 'manual validation required' : 'manual validation optional'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
