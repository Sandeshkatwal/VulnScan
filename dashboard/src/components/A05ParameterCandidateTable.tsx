import type { A05InjectionEvidenceItem } from '../types/api'

export function A05ParameterCandidateTable({ items = [] }: { items?: A05InjectionEvidenceItem[] }) {
  const rows = items.filter((item) => item.rule_group === 'parameter_candidates')
  if (!rows.length) return <div className="panel-message">No A05 parameter candidates are attached to this result.</div>
  return (
    <div className="table-shell">
      <table>
        <thead><tr><th>URL/path</th><th>Parameter</th><th>Candidate type</th><th>Potential issue</th><th>Confidence</th><th>Manual validation</th></tr></thead>
        <tbody>
          {rows.map((item) => (
            <tr key={item.evidence_id}>
              <td>{item.affected_url || '-'}</td>
              <td>{item.affected_parameter || '-'}</td>
              <td>{item.candidate_type || item.input_type || '-'}</td>
              <td>{item.potential_issue || item.title || '-'}</td>
              <td>{item.confidence || 'Low'}</td>
              <td>{item.manual_validation_required ? 'manual validation required' : 'indicator only'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
