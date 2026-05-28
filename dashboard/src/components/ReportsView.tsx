import { useCallback, useEffect, useMemo, useState } from 'react'
import { getCompletedJobs, getJobFindings, getJobResult } from '../api/client'
import type { FindingsResponse, JobResultResponse, JobSummary } from '../types/api'
import { formatDateTime } from '../utils/format'
import { buildReportSummary, hasReportFeature, reportProducingJobs } from '../utils/reportUtils'
import { ReportCard } from './ReportCard'
import { ReportMetadataPanel } from './ReportMetadataPanel'
import { ReportsTable } from './ReportsTable'

interface ReportsViewProps {
  apiOnline?: boolean
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Request failed.'
}

async function copyText(value?: string | null): Promise<boolean> {
  if (!value || !navigator.clipboard) return false
  await navigator.clipboard.writeText(value)
  return true
}

export function ReportsView({ apiOnline = true }: ReportsViewProps) {
  const [jobs, setJobs] = useState<JobSummary[]>([])
  const [selectedJob, setSelectedJob] = useState<JobSummary | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [loadedResults, setLoadedResults] = useState<Record<string, JobResultResponse>>({})
  const [loadedFindings, setLoadedFindings] = useState<Record<string, FindingsResponse>>({})
  const [resultLoadingJob, setResultLoadingJob] = useState<string | null>(null)
  const [findingsLoadingJob, setFindingsLoadingJob] = useState<string | null>(null)
  const [resultError, setResultError] = useState<string | null>(null)
  const [findingsError, setFindingsError] = useState<string | null>(null)
  const [copyMessage, setCopyMessage] = useState<string | null>(null)

  const loadReports = useCallback(async () => {
    if (!apiOnline) return
    setLoading(true)
    setError(null)
    try {
      const response = await getCompletedJobs(50)
      setJobs(response.jobs)
      setSelectedJob((current) => {
        if (current?.job_id && response.jobs.some((job) => job.job_id === current.job_id)) return current
        return reportProducingJobs(response.jobs)[0] || null
      })
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }, [apiOnline])

  useEffect(() => {
    void loadReports()
  }, [loadReports])

  const reportJobs = useMemo(() => reportProducingJobs(jobs), [jobs])

  const selectedJobId = selectedJob?.job_id || ''
  const selectedResult = selectedJobId ? loadedResults[selectedJobId] : undefined
  const selectedFindings = selectedJobId ? loadedFindings[selectedJobId] : undefined

  const loadResult = useCallback(async (job: JobSummary) => {
    if (!job.job_id) return
    setSelectedJob(job)
    setResultLoadingJob(job.job_id)
    setResultError(null)
    try {
      const result = await getJobResult(job.job_id)
      setLoadedResults((current) => ({ ...current, [job.job_id as string]: result }))
    } catch (caught) {
      setResultError(errorMessage(caught))
    } finally {
      setResultLoadingJob(null)
    }
  }, [])

  const loadFindings = useCallback(async (job: JobSummary) => {
    if (!job.job_id) return
    setSelectedJob(job)
    setFindingsLoadingJob(job.job_id)
    setFindingsError(null)
    try {
      const findings = await getJobFindings(job.job_id, { limit: 1, offset: 0, compact: false })
      setLoadedFindings((current) => ({ ...current, [job.job_id as string]: findings }))
    } catch (caught) {
      setFindingsError(errorMessage(caught))
    } finally {
      setFindingsLoadingJob(null)
    }
  }, [])

  async function handleCopy(label: string, value?: string | null) {
    setCopyMessage(null)
    try {
      const copied = await copyText(value)
      setCopyMessage(copied ? `${label} copied.` : 'Copy failed. Select and copy the path manually.')
    } catch {
      setCopyMessage('Copy failed. Select and copy the path manually.')
    }
  }

  const summaries = reportJobs.map((job) => buildReportSummary(job, job.job_id ? loadedResults[job.job_id] : undefined, job.job_id ? loadedFindings[job.job_id] : undefined))
  const latestReport = reportJobs[0]
  const jsonReports = summaries.filter((summary) => summary.has_json_report).length
  const htmlReports = summaries.filter((summary) => summary.has_html_report).length
  const fixFirstKnown = reportJobs.map((job) => hasReportFeature(job, 'fix_first_dashboard')).filter((value): value is boolean => value !== null)
  const trendKnown = reportJobs.map((job) => hasReportFeature(job, 'prioritisation_trends')).filter((value): value is boolean => value !== null)
  const fixFirstLoaded = summaries.filter((summary) => summary.has_fix_first_dashboard).length
  const trendLoaded = summaries.filter((summary) => summary.has_trend_data).length

  if (!apiOnline) {
    return <div className="empty-state">API offline. Reports View will load when the local API is reachable.</div>
  }

  return (
    <div className="reports-view">
      <div className="button-row button-row--right">
        <button className="secondary-button" type="button" onClick={() => void loadReports()} disabled={loading}>
          Refresh reports
        </button>
      </div>

      <div className="report-note">
        Local report paths may need to be opened from your file explorer or terminal. Browsers may block direct local file access.
        <code>Start-Process .\reports\REPORT_FILE.html</code>
      </div>

      <div className="report-card-grid">
        <ReportCard label="Total Completed Jobs" value={jobs.length} />
        <ReportCard label="JSON Reports Available" value={jsonReports} />
        <ReportCard label="HTML Reports Available" value={htmlReports} />
        <ReportCard label="Latest Report Target" value={latestReport?.target} />
        <ReportCard label="Latest Report Time" value={formatDateTime(latestReport?.completed_at)} />
        <ReportCard label="Reports With Fix-First Dashboard" value={fixFirstKnown.length ? fixFirstKnown.filter(Boolean).length : fixFirstLoaded || null} />
        <ReportCard label="Reports With Trend Data" value={trendKnown.length ? trendKnown.filter(Boolean).length : trendLoaded || null} />
      </div>

      {copyMessage ? <div className={copyMessage.startsWith('Copy failed') ? 'info-message' : 'success-message'}>{copyMessage}</div> : null}

      <ReportsTable
        jobs={reportJobs}
        selectedJobId={selectedJob?.job_id}
        loadedResults={loadedResults}
        loadedFindings={loadedFindings}
        loading={loading}
        error={error}
        onSelect={setSelectedJob}
        onLoadResult={loadResult}
        onLoadFindings={loadFindings}
        onCopy={handleCopy}
      />

      <ReportMetadataPanel
        job={selectedJob}
        result={selectedResult}
        findings={selectedFindings}
        resultLoading={Boolean(selectedJob?.job_id && resultLoadingJob === selectedJob.job_id)}
        findingsLoading={Boolean(selectedJob?.job_id && findingsLoadingJob === selectedJob.job_id)}
        resultError={resultError}
        findingsError={findingsError}
        onLoadResult={loadResult}
        onLoadFindings={loadFindings}
        onCopy={handleCopy}
      />
    </div>
  )
}
