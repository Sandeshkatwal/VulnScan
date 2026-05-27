import type { JobSummary } from '../types/api'

interface JobsTableProps {
  jobs: JobSummary[]
  loading?: boolean
  error?: string | null
}

function formatDate(value?: string): string {
  if (!value) return 'n/a'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function formatDuration(value?: number | null): string {
  if (value === null || value === undefined) return 'n/a'
  return `${Number(value).toFixed(2)}s`
}

function statusTone(status?: string): string {
  if (status === 'completed') return 'good'
  if (status === 'failed' || status === 'cancelled') return 'bad'
  if (status === 'running' || status === 'queued') return 'warn'
  return 'neutral'
}

export function JobsTable({ jobs, loading = false, error }: JobsTableProps) {
  if (loading) {
    return <div className="panel-message">Loading recent jobs...</div>
  }

  if (error) {
    return <div className="panel-message panel-message--error">{error}</div>
  }

  if (jobs.length === 0) {
    return <div className="panel-message">No API jobs found yet.</div>
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Job ID</th>
            <th>Target</th>
            <th>Status</th>
            <th>Created</th>
            <th>Completed</th>
            <th>Duration</th>
            <th>Result Path</th>
          </tr>
        </thead>
        <tbody>
          {jobs.map((job) => (
            <tr key={job.job_id || `${job.target}-${job.created_at}`}>
              <td className="mono">{job.job_id || 'n/a'}</td>
              <td>{job.target || 'n/a'}</td>
              <td>
                <span className={`badge badge--${statusTone(job.status)}`}>{job.status || 'unknown'}</span>
              </td>
              <td>{formatDate(job.created_at)}</td>
              <td>{formatDate(job.completed_at)}</td>
              <td>{formatDuration(job.duration_seconds)}</td>
              <td className="path-cell">{job.result_path || 'n/a'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
