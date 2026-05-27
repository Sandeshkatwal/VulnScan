import type { Finding } from '../types/api'
import { formatValue, getCve, getCvss, getEpss, getExploitAvailable } from '../utils/format'
import { FindingBadge } from './FindingBadge'
import { LoadingSpinner } from './LoadingSpinner'

interface FindingsTableProps {
  findings: Finding[]
  loading?: boolean
  error?: string | null
  sortBy?: string
  sortOrder?: string
  onSort?: (sortBy: string) => void
  onSelectFinding?: (finding: Finding) => void
}

const sortableFields = new Set(['severity', 'risk_score', 'priority_score', 'title', 'source', 'category'])

export function FindingsTable({
  findings,
  loading = false,
  error,
  sortBy,
  sortOrder,
  onSort,
  onSelectFinding,
}: FindingsTableProps) {
  if (loading) {
    return (
      <div className="panel-message">
        <LoadingSpinner label="Loading findings" />
      </div>
    )
  }

  if (error) {
    return <div className="panel-message panel-message--error">{error}</div>
  }

  if (findings.length === 0) return <div className="panel-message">No findings match the current filters.</div>

  function header(label: string, field?: string) {
    const active = field && sortBy === field
    const suffix = active ? (sortOrder === 'asc' ? ' up' : ' down') : ''
    if (!field || !sortableFields.has(field)) return <th>{label}</th>
    return (
      <th>
        <button className="table-sort-button" type="button" onClick={() => onSort?.(field)}>
          {label}{suffix}
        </button>
      </th>
    )
  }

  return (
    <div className="table-wrap">
      <table className="findings-table">
        <thead>
          <tr>
            {header('Title', 'title')}
            {header('Severity', 'severity')}
            {header('Source', 'source')}
            {header('Category', 'category')}
            {header('Risk', 'risk_score')}
            {header('Priority Score', 'priority_score')}
            {header('Priority')}
            {header('CVE')}
            {header('CVSS')}
            {header('EPSS')}
            {header('Exploit')}
            {header('Action')}
          </tr>
        </thead>
        <tbody>
          {findings.map((finding, index) => (
            <tr key={`${finding.finding_id || finding.title || 'finding'}-${index}`}>
              <td>{formatValue(finding.title)}</td>
              <td><FindingBadge type="severity" value={finding.severity} /></td>
              <td>{formatValue(finding.source)}</td>
              <td>{formatValue(finding.category)}</td>
              <td>{formatValue(finding.risk_score)}</td>
              <td>{formatValue(finding.priority_score)}</td>
              <td><FindingBadge type="priority" value={finding.priority_label} /></td>
              <td>{getCve(finding)}</td>
              <td>{getCvss(finding)}</td>
              <td>{getEpss(finding)}</td>
              <td><FindingBadge type="exploit" value={getExploitAvailable(finding)} /></td>
              <td>
                <button className="ghost-button compact-button" type="button" onClick={() => onSelectFinding?.(finding)}>
                  View Details
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
