import type { A03SupplyChainEvidenceItem, A03SupplyChainSummary } from '../types/api'

export function A03SBOMPanel({ summary, items = [] }: { summary: A03SupplyChainSummary; items?: A03SupplyChainEvidenceItem[] }) {
  const rows = items.filter((item) => item.rule_group === 'sbom_analysis')
  const withVersions = rows.filter((item) => item.component_version).length
  const withIdentity = rows.filter((item) => item.cpe || item.purl).length
  return (
    <div className="a03-sbom-panel">
      <div className="a03-mini-grid">
        <div><strong>{summary.sbom_component_count || rows.length}</strong><span>Imported components</span></div>
        <div><strong>{withVersions}</strong><span>With versions</span></div>
        <div><strong>{withIdentity}</strong><span>With CPE/PURL</span></div>
        <div><strong>{summary.cve_match_count || 0}</strong><span>CVE matches</span></div>
      </div>
      {!rows.length ? <div className="panel-message">No SBOM analysis evidence is attached to this result.</div> : (
        <div className="a03-list">
          {rows.slice(0, 20).map((item) => (
            <div className="a03-list-item" key={item.evidence_id}>
              <strong>{item.component_name || 'component'} {item.component_version || ''}</strong>
              <span>{item.purl || item.cpe || item.component_type || 'component metadata'}</span>
              <small>{item.cve_ids?.length ? `CVE evidence: ${item.cve_ids.join(', ')}` : 'No CVE match attached.'}</small>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
