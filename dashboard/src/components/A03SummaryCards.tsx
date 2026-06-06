import type { A03SupplyChainSummary } from '../types/api'

export function A03SummaryCards({ summary }: { summary: A03SupplyChainSummary }) {
  const cards = [
    ['Total A03 evidence', summary.total_evidence_items || 0],
    ['Component hints', summary.component_hint_count || 0],
    ['Version exposures', summary.version_exposure_count || 0],
    ['Dependency metadata', summary.dependency_metadata_exposure_count || 0],
    ['SBOM components', summary.sbom_component_count || 0],
    ['CVE matches', summary.cve_match_count || 0],
    ['Source maps', summary.source_map_indicator_count || 0],
    ['Manual validation', summary.manual_validation_required_count || 0],
  ]
  return (
    <div className="a03-summary-grid">
      {cards.map(([label, value]) => (
        <div className="metric" key={String(label)}>
          <div className="label">{label}</div>
          <div className="value">{value}</div>
        </div>
      ))}
    </div>
  )
}
