import type { A03SupplyChainEvidenceItem } from '../types/api'
import { A03ConfidenceBadge } from './A03ConfidenceBadge'

export function A03ComponentEvidenceTable({ items = [] }: { items?: A03SupplyChainEvidenceItem[] }) {
  const rows = items.filter((item) => ['javascript_library_hints', 'component_version_exposure'].includes(item.rule_group || ''))
  if (!rows.length) return <div className="panel-message">No A03 component hint or version exposure evidence is attached to this result.</div>
  return (
    <div className="table-shell">
      <table>
        <thead><tr><th>Component</th><th>Version</th><th>Source</th><th>Confidence</th><th>CVE count</th><th>Recommendation</th></tr></thead>
        <tbody>
          {rows.map((item) => (
            <tr key={item.evidence_id || `${item.component_name}-${item.affected_url}`}>
              <td>{item.component_name || 'component'}</td>
              <td>{item.component_version || 'unknown'}</td>
              <td>{item.affected_url || item.affected_host || 'metadata'}</td>
              <td><A03ConfidenceBadge confidence={item.confidence} /></td>
              <td>{item.cve_ids?.length || 0}</td>
              <td>{item.recommendation || 'Review component version and patch status.'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
