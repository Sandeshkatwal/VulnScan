import type { A01AccessControlEvidenceItem } from '../types/api'

export function A01AdminSurfaceTable({ items }: { items: A01AccessControlEvidenceItem[] }) {
  const rows = items.filter((item) => item.rule_group === 'function_level_authorization_candidates')
  if (!rows.length) return <div className="panel-message">No admin or function-level authorization candidates are attached to this result.</div>
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Endpoint</th><th>Function type</th><th>Candidate reason</th><th>Score</th><th>Recommendation</th></tr></thead>
        <tbody>
          {rows.map((item) => (
            <tr key={item.evidence_id}>
              <td>{item.affected_url || 'endpoint unavailable'}</td>
              <td>{item.endpoint_category || item.access_control_candidate_type || 'function surface'}</td>
              <td>{item.safe_evidence_summary || item.title}</td>
              <td>{item.candidate_score || 0}</td>
              <td>{item.recommendation || 'Manually validate authorization using authorised roles.'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
