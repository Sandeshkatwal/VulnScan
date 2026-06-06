import type { A03SupplyChainEvidenceItem } from '../types/api'
import { A03ConfidenceBadge } from './A03ConfidenceBadge'

export function A03DependencyMetadataPanel({ items = [] }: { items?: A03SupplyChainEvidenceItem[] }) {
  const rows = items.filter((item) => item.rule_group === 'dependency_metadata_exposure')
  if (!rows.length) return <div className="panel-message">No dependency metadata exposure indicators are attached to this result.</div>
  return (
    <div className="table-shell">
      <table>
        <thead><tr><th>File</th><th>URL/source</th><th>Exposure type</th><th>Confidence</th><th>Recommendation</th></tr></thead>
        <tbody>
          {rows.map((item) => (
            <tr key={item.evidence_id || item.affected_url}>
              <td>{item.metadata_filename || item.component_name}</td>
              <td>{item.affected_url || 'discovered metadata'}</td>
              <td>{item.rule_id}</td>
              <td><A03ConfidenceBadge confidence={item.confidence} /></td>
              <td>{item.recommendation || 'Avoid exposing dependency metadata publicly unless intentionally published.'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
