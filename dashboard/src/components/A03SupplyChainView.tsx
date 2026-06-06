import type { A03SupplyChainEvidenceItem, A03SupplyChainSummary } from '../types/api'
import { A03ComponentEvidenceTable } from './A03ComponentEvidenceTable'
import { A03CVEEnrichmentTable } from './A03CVEEnrichmentTable'
import { A03DependencyMetadataPanel } from './A03DependencyMetadataPanel'
import { A03RecommendationPanel } from './A03RecommendationPanel'
import { A03SBOMPanel } from './A03SBOMPanel'
import { A03SummaryCards } from './A03SummaryCards'

export function A03SupplyChainView({ summary, evidence = [] }: { summary?: A03SupplyChainSummary; evidence?: A03SupplyChainEvidenceItem[] }) {
  if (!summary?.enabled) {
    return (
      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>A03 Software Supply Chain</h2>
          <p>A03 evidence is available when a scan or report is generated with A03 checks or SBOM analysis.</p>
        </div>
        <div className="panel-message">No A03 Software Supply Chain evidence is attached to the selected result.</div>
      </article>
    )
  }
  const processRows = evidence.filter((item) => item.rule_group === 'supply_chain_process_manual_review')
  return (
    <article className="panel panel--wide a03-panel">
      <div className="panel-heading">
        <div>
          <h2>A03 Software Supply Chain</h2>
          <p>Component exposure indicators, dependency metadata indicators, SBOM analysis, and local vulnerability intelligence enrichment.</p>
        </div>
      </div>
      <A03SummaryCards summary={summary} />
      <p className="panel-message">Evidence-based review only. Manual validation required for impact; no exploit code used and no external registry fetching in this version.</p>
      <h3>Component Evidence</h3>
      <A03ComponentEvidenceTable items={evidence} />
      <h3>Dependency Metadata</h3>
      <A03DependencyMetadataPanel items={evidence} />
      <h3>SBOM Analysis</h3>
      <A03SBOMPanel summary={summary} items={evidence} />
      <h3>CVE/CPE Enrichment</h3>
      <A03CVEEnrichmentTable items={evidence} />
      <h3>Source Map, Build Artifact, and Third-Party Script Review</h3>
      {!processRows.length ? <div className="panel-message">No source map, build artifact, or third-party script review indicators are attached to this result.</div> : (
        <div className="a03-list">
          {processRows.map((item) => (
            <div className="a03-list-item" key={item.evidence_id}>
              <strong>{item.title || item.component_name}</strong>
              <span>{item.affected_url || item.affected_host || item.component_type}</span>
              <small>{item.safe_evidence_summary || 'manual validation required'}</small>
            </div>
          ))}
        </div>
      )}
      <h3>Recommendations</h3>
      <A03RecommendationPanel summary={summary} />
    </article>
  )
}
