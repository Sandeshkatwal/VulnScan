import type { A05InjectionEvidenceItem } from '../types/api'
import { A05ContextBadge } from './A05ContextBadge'

export function A05ReflectionEvidenceTable({ items = [] }: { items?: A05InjectionEvidenceItem[] }) {
  const rows = items.filter((item) => item.rule_group === 'reflection_observation')
  if (!rows.length) return <div className="panel-message">No harmless marker reflection observations are attached to this result.</div>
  return (
    <div className="table-shell">
      <table>
        <thead><tr><th>URL</th><th>Parameter</th><th>Marker reflected</th><th>Context</th><th>Strength</th><th>Confidence</th><th>Redacted snippet</th></tr></thead>
        <tbody>
          {rows.map((item) => (
            <tr key={item.evidence_id}>
              <td>{item.affected_url || '-'}</td>
              <td>{item.affected_parameter || '-'}</td>
              <td>{item.marker_reflected ? 'yes' : 'indicator'}</td>
              <td><A05ContextBadge value={item.reflection_context} /></td>
              <td>{item.evidence_strength || '-'}</td>
              <td>{item.confidence || 'Low'}</td>
              <td>{item.redacted_snippet || 'Full response body was not stored.'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
