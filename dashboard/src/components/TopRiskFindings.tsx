import type { Finding } from '../types/api'
import { formatValue, getCve } from '../utils/format'
import { FindingBadge } from './FindingBadge'

interface TopRiskFindingsProps {
  findings: Finding[]
  onSelectFinding: (finding: Finding) => void
}

export function TopRiskFindings({ findings, onSelectFinding }: TopRiskFindingsProps) {
  if (findings.length === 0) {
    return <div className="panel-message">No findings available for this job.</div>
  }

  return (
    <div className="top-risk-list">
      {findings.map((finding, index) => (
        <button
          className="top-risk-item"
          key={`${finding.finding_id || finding.id || finding.title || 'finding'}-${index}`}
          type="button"
          onClick={() => onSelectFinding(finding)}
        >
          <div className="top-risk-item__header">
            <strong>{formatValue(finding.title)}</strong>
            <FindingBadge type="severity" value={finding.severity} />
          </div>
          <dl>
            <div>
              <dt>Priority</dt>
              <dd><FindingBadge type="priority" value={finding.priority_label} /></dd>
            </div>
            <div>
              <dt>Priority Score</dt>
              <dd>{formatValue(finding.priority_score)}</dd>
            </div>
            <div>
              <dt>Source</dt>
              <dd>{formatValue(finding.source)}</dd>
            </div>
            <div>
              <dt>CVE</dt>
              <dd>{getCve(finding)}</dd>
            </div>
          </dl>
          <p>{formatValue(finding.recommended_action ?? finding.recommendation)}</p>
        </button>
      ))}
    </div>
  )
}
