import type { Finding } from '../types/api'
import { LoadingSpinner } from './LoadingSpinner'

interface FindingsTableProps {
  findings: Finding[]
  loading?: boolean
  error?: string | null
}

function toneForSeverity(severity?: string): string {
  if (severity === 'Critical' || severity === 'High') return 'bad'
  if (severity === 'Medium') return 'warn'
  if (severity === 'Low') return 'neutral'
  return 'good'
}

function toneForPriority(priority?: string): string {
  if (priority === 'Fix First') return 'bad'
  if (priority === 'Fix Soon' || priority === 'Schedule') return 'warn'
  if (priority === 'Monitor') return 'neutral'
  return 'good'
}

function valueOrBlank(value: unknown): string {
  if (value === null || value === undefined || value === '') return 'n/a'
  return String(value)
}

export function FindingsTable({ findings, loading = false, error }: FindingsTableProps) {
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

  if (findings.length === 0) {
    return <div className="panel-message">No findings loaded for the selected job.</div>
  }

  return (
    <div className="table-wrap">
      <table className="findings-table">
        <thead>
          <tr>
            <th>Title</th>
            <th>Severity</th>
            <th>Source</th>
            <th>Category</th>
            <th>Risk</th>
            <th>Priority Score</th>
            <th>Priority</th>
            <th>Recommendation</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding, index) => (
            <tr key={`${finding.finding_id || finding.title || 'finding'}-${index}`}>
              <td>{valueOrBlank(finding.title)}</td>
              <td>
                <span className={`badge badge--${toneForSeverity(finding.severity)}`}>
                  {valueOrBlank(finding.severity)}
                </span>
              </td>
              <td>{valueOrBlank(finding.source)}</td>
              <td>{valueOrBlank(finding.category)}</td>
              <td>{valueOrBlank(finding.risk_score)}</td>
              <td>{valueOrBlank(finding.priority_score)}</td>
              <td>
                <span className={`badge badge--${toneForPriority(finding.priority_label)}`}>
                  {valueOrBlank(finding.priority_label)}
                </span>
              </td>
              <td className="recommendation-cell">{valueOrBlank(finding.recommendation)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
