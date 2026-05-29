import type { FindingsResponse, JobResultResponse, JobSummary, ReportMetadata } from '../types/api'
import { formatDateTime, formatValue } from '../utils/format'
import { buildReportMetadata } from '../utils/reportUtils'
import { ReportPathBadge } from './ReportPathBadge'

interface ReportMetadataPanelProps {
  job?: JobSummary | null
  result?: JobResultResponse | null
  findings?: FindingsResponse | null
  resultLoading?: boolean
  findingsLoading?: boolean
  resultError?: string | null
  findingsError?: string | null
  onLoadResult: (job: JobSummary) => void
  onLoadFindings: (job: JobSummary) => void
  onCopy: (label: string, value?: string | null) => void
  onViewReport: (path?: string | null, filename?: string) => void
  onDownloadReport: (path?: string | null, filename?: string) => void
}

function SectionSummary({ title, value }: { title: string; value?: Record<string, unknown> | null }) {
  if (!value || !Object.keys(value).length) {
    return (
      <div className="report-metadata-section">
        <h3>{title}</h3>
        <div className="context-card__message">Not available</div>
      </div>
    )
  }

  const entries = Object.entries(value).slice(0, 8)
  return (
    <div className="report-metadata-section">
      <h3>{title}</h3>
      <dl className="context-card__grid">
        {entries.map(([key, item]) => (
          <div key={key}>
            <dt>{key.replaceAll('_', ' ')}</dt>
            <dd>{formatValue(item)}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}

export function ReportMetadataPanel({
  job,
  result,
  findings,
  resultLoading = false,
  findingsLoading = false,
  resultError,
  findingsError,
  onLoadResult,
  onLoadFindings,
  onCopy,
  onViewReport,
  onDownloadReport,
}: ReportMetadataPanelProps) {
  if (!job) return <div className="empty-state">Select a report-producing job to view report metadata.</div>

  const metadata: ReportMetadata = buildReportMetadata(job, result, findings)
  const summary = metadata.report_summary

  return (
    <div className="report-metadata-panel">
      <div className="report-metadata-actions">
        <button className="secondary-button" type="button" onClick={() => onLoadResult(job)} disabled={resultLoading || !job.job_id}>
          {resultLoading ? 'Loading result...' : 'Load result'}
        </button>
        <button className="secondary-button" type="button" onClick={() => onLoadFindings(job)} disabled={findingsLoading || !job.job_id}>
          {findingsLoading ? 'Loading findings...' : 'Load findings'}
        </button>
        <button className="ghost-button" type="button" onClick={() => onCopy('JSON path', job.result_path)} disabled={!job.result_path}>
          Copy JSON path
        </button>
        <button className="ghost-button" type="button" onClick={() => onCopy('HTML path', job.html_report_path)} disabled={!job.html_report_path}>
          Copy HTML path
        </button>
        <button className="ghost-button" type="button" onClick={() => onViewReport(job.html_view_url, job.html_report_path || 'vulscan-report.html')} disabled={!job.html_view_url}>
          View HTML report
        </button>
        <button className="ghost-button" type="button" onClick={() => onDownloadReport(job.html_download_url, job.html_report_path || 'vulscan-report.html')} disabled={!job.html_download_url}>
          Download HTML report
        </button>
        <button className="ghost-button" type="button" onClick={() => onDownloadReport(job.result_download_url, job.result_path || 'vulscan-report.json')} disabled={!job.result_download_url}>
          Download JSON report
        </button>
        <button className="ghost-button" type="button" onClick={() => onCopy('Job ID', job.job_id)} disabled={!job.job_id}>
          Copy job ID
        </button>
        <button className="ghost-button" type="button" onClick={() => onCopy('Scan ID', job.scan_id)} disabled={!job.scan_id}>
          Copy scan ID
        </button>
      </div>

      {resultError ? <div className="panel-message panel-message--error">Result unavailable.</div> : null}
      {findingsError ? <div className="panel-message panel-message--error">Findings unavailable.</div> : null}
      {!job.result_path && !job.html_report_path ? (
        <div className="info-message">This job completed but no JSON/HTML report path was returned.</div>
      ) : null}

      <dl className="report-metadata-grid">
        <div><dt>Job ID</dt><dd>{formatValue(job.job_id)}</dd></div>
        <div><dt>Scan ID</dt><dd>{formatValue(job.scan_id)}</dd></div>
        <div><dt>Target</dt><dd>{formatValue(job.target)}</dd></div>
        <div><dt>Status</dt><dd>{formatValue(job.status)}</dd></div>
        <div><dt>Duration</dt><dd>{formatValue(summary?.duration_seconds)}</dd></div>
        <div><dt>Completed</dt><dd>{formatDateTime(job.completed_at)}</dd></div>
        <div><dt>Result Path</dt><dd><ReportPathBadge label="JSON" path={job.result_path} /></dd></div>
        <div><dt>HTML Path</dt><dd><ReportPathBadge label="HTML" path={job.html_report_path} /></dd></div>
        <div><dt>Findings Count</dt><dd>{formatValue(summary?.findings_count)}</dd></div>
        <div><dt>Fix-First Dashboard</dt><dd>{formatValue(summary?.has_fix_first_dashboard)}</dd></div>
        <div><dt>Trend Data</dt><dd>{formatValue(summary?.has_trend_data)}</dd></div>
        <div><dt>Vulnerability Intelligence</dt><dd>{formatValue(summary?.has_vuln_intel)}</dd></div>
        <div><dt>Web DAST</dt><dd>{formatValue(summary?.has_web_dast)}</dd></div>
      </dl>

      <div className="report-section-grid">
        <SectionSummary title="Prioritisation Summary" value={metadata.prioritisation_summary} />
        <SectionSummary title="Fix-First Dashboard" value={metadata.fix_first_dashboard} />
        <SectionSummary title="Prioritisation Trends" value={metadata.prioritisation_trends} />
        <SectionSummary title="Vulnerability Intelligence" value={metadata.vulnerability_intelligence} />
        <SectionSummary title="Web DAST Summary" value={metadata.web_dast_summary} />
        <SectionSummary title="Asset Context" value={metadata.asset_context} />
      </div>
    </div>
  )
}
