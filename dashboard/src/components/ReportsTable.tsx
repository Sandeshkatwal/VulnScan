import type { FindingsResponse, JobResultResponse, JobSummary } from '../types/api'
import { formatDateTime, formatValue } from '../utils/format'
import { buildReportSummary } from '../utils/reportUtils'
import { ReportPathBadge } from './ReportPathBadge'
import { statusTone } from './JobsTable'

interface ReportsTableProps {
  jobs: JobSummary[]
  selectedJobId?: string | null
  loadedResults: Record<string, JobResultResponse>
  loadedFindings: Record<string, FindingsResponse>
  loading?: boolean
  error?: string | null
  onSelect: (job: JobSummary) => void
  onLoadResult: (job: JobSummary) => void
  onLoadFindings: (job: JobSummary) => void
  onCopy: (label: string, value?: string | null) => void
  onViewReport: (path?: string | null, filename?: string) => void
  onDownloadReport: (path?: string | null, filename?: string) => void
}

function formatDuration(value?: number | null): string {
  if (value === null || value === undefined) return 'Not available'
  return `${Number(value).toFixed(2)}s`
}

export function ReportsTable({
  jobs,
  selectedJobId,
  loadedResults,
  loadedFindings,
  loading = false,
  error,
  onSelect,
  onLoadResult,
  onLoadFindings,
  onCopy,
  onViewReport,
  onDownloadReport,
}: ReportsTableProps) {
  if (loading) return <div className="panel-message">Loading saved reports...</div>
  if (error) return <div className="panel-message panel-message--error">{error}</div>
  if (jobs.length === 0) return <div className="empty-state">No saved reports found. Run a scan with JSON or HTML report enabled.</div>

  return (
    <div className="table-wrap">
      <table className="reports-table">
        <thead>
          <tr>
            <th>Target</th>
            <th>Job ID</th>
            <th>Scan ID</th>
            <th>Status</th>
            <th>Completed</th>
            <th>JSON Report</th>
            <th>HTML Report</th>
            <th>Findings</th>
            <th>Duration</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {jobs.map((job) => {
            const jobId = job.job_id || ''
            const summary = buildReportSummary(job, loadedResults[jobId], loadedFindings[jobId])
            return (
              <tr
                key={jobId || `${job.target}-${job.completed_at}`}
                className={selectedJobId && selectedJobId === jobId ? 'selected-row' : undefined}
                onClick={() => onSelect(job)}
              >
                <td>{formatValue(job.target)}</td>
                <td className="mono">{formatValue(job.job_id)}</td>
                <td className="mono">{formatValue(job.scan_id)}</td>
                <td><span className={`badge badge--${statusTone(job.status)}`}>{job.status || 'unknown'}</span></td>
                <td>{formatDateTime(job.completed_at)}</td>
                <td><ReportPathBadge label="JSON" path={job.result_path} /></td>
                <td><ReportPathBadge label="HTML" path={job.html_report_path} /></td>
                <td>{formatValue(summary.findings_count)}</td>
                <td>{formatDuration(job.duration_seconds)}</td>
                <td>
                  <div className="report-actions">
                    <button className="ghost-button compact-button" type="button" onClick={(event) => { event.stopPropagation(); onLoadResult(job) }}>
                      Load result
                    </button>
                    <button className="ghost-button compact-button" type="button" onClick={(event) => { event.stopPropagation(); onLoadFindings(job) }}>
                      Load findings
                    </button>
                    <button className="ghost-button compact-button" type="button" disabled={!job.html_view_url} onClick={(event) => { event.stopPropagation(); onViewReport(job.html_view_url, job.html_report_path || 'vulscan-report.html') }}>
                      View HTML
                    </button>
                    <button className="ghost-button compact-button" type="button" disabled={!job.html_download_url} onClick={(event) => { event.stopPropagation(); onDownloadReport(job.html_download_url, job.html_report_path || 'vulscan-report.html') }}>
                      Download HTML
                    </button>
                    <button className="ghost-button compact-button" type="button" disabled={!job.result_download_url} onClick={(event) => { event.stopPropagation(); onDownloadReport(job.result_download_url, job.result_path || 'vulscan-report.json') }}>
                      Download JSON
                    </button>
                    <button className="ghost-button compact-button" type="button" disabled={!job.result_path} onClick={(event) => { event.stopPropagation(); onCopy('JSON path', job.result_path) }}>
                      Copy JSON path
                    </button>
                    <button className="ghost-button compact-button" type="button" disabled={!job.html_report_path} onClick={(event) => { event.stopPropagation(); onCopy('HTML path', job.html_report_path) }}>
                      Copy HTML path
                    </button>
                  </div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
