import type { ApiRecord, JobResultResponse, JobSummary } from '../types/api'
import { ErrorAlert } from './ErrorAlert'
import { LoadingSpinner } from './LoadingSpinner'

interface JobDetailsProps {
  job: JobSummary | null
  result: JobResultResponse | null
  resultLoading?: boolean
  resultError?: string | null
  onRefreshJob: () => void
  onLoadResult: () => void
  onLoadFindings: () => void
}

function formatDate(value?: string): string {
  if (!value) return 'n/a'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return 'n/a'
  if (typeof value === 'number') return Number.isInteger(value) ? String(value) : value.toFixed(2)
  return String(value)
}

function isPending(job: JobSummary): boolean {
  return job.status === 'queued' || job.status === 'running'
}

function resultSummary(result: JobResultResponse | null): ApiRecord | null {
  const payload = result?.result
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null
  const summary = payload.summary
  if (summary && typeof summary === 'object' && !Array.isArray(summary)) {
    return summary as ApiRecord
  }
  return payload
}

export function JobDetails({
  job,
  result,
  resultLoading = false,
  resultError,
  onRefreshJob,
  onLoadResult,
  onLoadFindings,
}: JobDetailsProps) {
  if (!job) {
    return <div className="empty-state">Select a job to inspect status, result metadata, and findings.</div>
  }

  const pending = isPending(job)
  const completed = job.status === 'completed'
  const summary = resultSummary(result)

  return (
    <div className="job-details">
      <ErrorAlert message={resultError} />
      {pending ? <div className="info-message">Scan is still running.</div> : null}
      {job.status === 'failed' && job.error_message ? <ErrorAlert message={job.error_message} /> : null}

      <dl>
        <div>
          <dt>Job ID</dt>
          <dd className="mono">{job.job_id || 'n/a'}</dd>
        </div>
        <div>
          <dt>Target</dt>
          <dd>{job.target || 'n/a'}</dd>
        </div>
        <div>
          <dt>Status</dt>
          <dd>{job.status || 'unknown'}</dd>
        </div>
        <div>
          <dt>Created</dt>
          <dd>{formatDate(job.created_at)}</dd>
        </div>
        <div>
          <dt>Started</dt>
          <dd>{formatDate(job.started_at)}</dd>
        </div>
        <div>
          <dt>Completed</dt>
          <dd>{formatDate(job.completed_at)}</dd>
        </div>
        <div>
          <dt>Duration</dt>
          <dd>{formatValue(job.duration_seconds)}{job.duration_seconds ? 's' : ''}</dd>
        </div>
        <div>
          <dt>Result Path</dt>
          <dd className="path-cell">{job.result_path || 'n/a'}</dd>
        </div>
        <div>
          <dt>HTML Report</dt>
          <dd className="path-cell">{job.html_report_path || 'n/a'}</dd>
        </div>
      </dl>

      <div className="button-row">
        <button className="secondary-button" type="button" onClick={onRefreshJob}>
          Refresh job
        </button>
        <button className="secondary-button" type="button" onClick={onLoadResult} disabled={!completed || resultLoading}>
          {resultLoading ? <LoadingSpinner label="Loading result" /> : 'Load result'}
        </button>
        <button className="secondary-button" type="button" onClick={onLoadFindings} disabled={!completed}>
          Load findings
        </button>
      </div>

      {result?.message ? <div className="info-message">{result.message}</div> : null}
      {summary ? (
        <div className="result-summary">
          <h3>Result Summary</h3>
          <dl>
            {Object.entries(summary)
              .slice(0, 12)
              .map(([key, value]) => (
                <div key={key}>
                  <dt>{key}</dt>
                  <dd>{formatValue(value)}</dd>
                </div>
              ))}
          </dl>
        </div>
      ) : null}
    </div>
  )
}
