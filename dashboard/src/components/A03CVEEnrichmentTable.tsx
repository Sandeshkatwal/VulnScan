import type { A03SupplyChainEvidenceItem } from '../types/api'
import { A03ConfidenceBadge } from './A03ConfidenceBadge'

export function A03CVEEnrichmentTable({ items = [] }: { items?: A03SupplyChainEvidenceItem[] }) {
  const rows = items.filter((item) => (item.cve_ids?.length || 0) > 0)
  if (!rows.length) return <div className="panel-message">No CVE/CPE enrichment evidence is attached to this result.</div>
  return (
    <div className="table-shell">
      <table>
        <thead><tr><th>Component</th><th>CPE/PURL</th><th>CVE</th><th>CVSS</th><th>EPSS</th><th>Exploit metadata</th><th>Confidence</th></tr></thead>
        <tbody>
          {rows.flatMap((item) => (item.cve_ids || []).map((cve) => (
            <tr key={`${item.evidence_id}-${cve}`}>
              <td>{item.component_name || 'component'} {item.component_version || ''}</td>
              <td>{item.cpe || item.purl || 'identity unavailable'}</td>
              <td>{cve}</td>
              <td>{item.cvss_score ?? 'n/a'}</td>
              <td>{item.epss_score ?? 'n/a'}</td>
              <td>{item.exploit_metadata?.available ? 'metadata available' : 'none attached'}</td>
              <td><A03ConfidenceBadge confidence={item.confidence} /></td>
            </tr>
          )))}
        </tbody>
      </table>
    </div>
  )
}
