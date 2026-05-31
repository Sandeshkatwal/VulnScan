import type { Finding } from '../types/api'

interface ReconFindingPanelProps {
  findings: Finding[]
}

export function ReconFindingPanel({ findings }: ReconFindingPanelProps) {
  return (
    <div className="recon-findings">
      {findings.slice(0, 3).map((finding, index) => (
        <div className="panel-message" key={`${finding.title || 'finding'}-${index}`}>
          <strong>{finding.title || 'Recon finding'}</strong>
          <span>{finding.evidence || finding.recommendation || 'Review recon output.'}</span>
        </div>
      ))}
      {!findings.length ? <div className="empty-state">Recon findings will appear after a run.</div> : null}
    </div>
  )
}
