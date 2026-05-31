import { useCallback, useEffect, useMemo, useState } from 'react'
import { authenticatedDownload, getCompletedJobs, getJobFindings, getJobResult, getReports } from '../api/client'
import type { Finding, FindingsResponse, JobResultResponse, JobSummary, ReportFileSummary } from '../types/api'
import { formatDateTime } from '../utils/format'
import { buildReportSummary, hasReportFeature, reportProducingJobs } from '../utils/reportUtils'
import { ReportCard } from './ReportCard'
import { ReportMetadataPanel } from './ReportMetadataPanel'
import { ReportsTable } from './ReportsTable'

interface ReportsViewProps {
  apiOnline?: boolean
  demoMode?: boolean
  demoJobs?: JobSummary[]
  demoResult?: JobResultResponse
  demoFindings?: Finding[]
}

const emptyDemoJobs: JobSummary[] = []
const emptyDemoFindings: Finding[] = []

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Request failed.'
}

async function copyText(value?: string | null): Promise<boolean> {
  if (!value || !navigator.clipboard) return false
  await navigator.clipboard.writeText(value)
  return true
}

export function ReportsView({ apiOnline = true, demoMode = false, demoJobs = emptyDemoJobs, demoResult, demoFindings = emptyDemoFindings }: ReportsViewProps) {
  const [jobs, setJobs] = useState<JobSummary[]>([])
  const [apiReports, setApiReports] = useState<ReportFileSummary[]>([])
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
    if (demoMode) {
      setJobs(demoJobs)
      setApiReports([
        { report_id: 'demo-report-json', filename: 'demo_report.json', type: 'json', target: 'demo-web.local', created_at: '2026-05-29T09:01:18+00:00', size_bytes: 24576 },
        { report_id: 'demo-report-html', filename: 'demo_report.html', type: 'html', target: 'demo-web.local', created_at: '2026-05-29T09:01:18+00:00', size_bytes: 32768 },
      ])
      setLoadedResults(demoResult && demoJobs[0]?.job_id ? { [demoJobs[0].job_id as string]: demoResult } : {})
      setLoadedFindings(demoJobs[0]?.job_id ? { [demoJobs[0].job_id as string]: { findings: demoFindings } } : {})
      setSelectedJob(demoJobs[0] || null)
      return
    }
    if (!apiOnline) return
    setLoading(true)
    setError(null)
    try {
      const [jobsResponse, reportsResponse] = await Promise.allSettled([
        getCompletedJobs(50),
        getReports({ limit: 50, type: 'all' }),
      ])
      if (jobsResponse.status === 'rejected') throw jobsResponse.reason
      setJobs(jobsResponse.value.jobs)
      setApiReports(reportsResponse.status === 'fulfilled' ? reportsResponse.value.reports : [])
      setSelectedJob((current) => {
        if (current?.job_id && jobsResponse.value.jobs.some((job) => job.job_id === current.job_id)) return current
        return reportProducingJobs(jobsResponse.value.jobs)[0] || null
      })
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }, [apiOnline, demoFindings, demoJobs, demoMode, demoResult])

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

  async function handleViewReport(path?: string | null, filename?: string) {
    if (!path) return
    if (demoMode) {
      setCopyMessage('Demo report path only.')
      return
    }
    setCopyMessage(null)
    try {
      await authenticatedDownload(path, filename || 'vulscan-report.html', true)
    } catch {
      setCopyMessage('Report could not be opened through the authenticated API.')
    }
  }

  async function handleDownloadReport(path?: string | null, filename?: string) {
    if (!path) return
    if (demoMode) {
      setCopyMessage('Demo report path only.')
      return
    }
    setCopyMessage(null)
    try {
      await authenticatedDownload(path, filename || 'vulscan-report')
      setCopyMessage('Report download started.')
    } catch {
      setCopyMessage('Report download failed. Copy the path and try from the API or terminal.')
    }
  }

  const summaries = reportJobs.map((job) => buildReportSummary(job, job.job_id ? loadedResults[job.job_id] : undefined, job.job_id ? loadedFindings[job.job_id] : undefined))
  const latestReport = reportJobs[0]
  const jsonReports = summaries.filter((summary) => summary.has_json_report).length
  const htmlReports = summaries.filter((summary) => summary.has_html_report).length
  const indexedJsonReports = apiReports.filter((report) => report.type === 'json').length
  const indexedHtmlReports = apiReports.filter((report) => report.type === 'html').length
  const fixFirstKnown = reportJobs.map((job) => hasReportFeature(job, 'fix_first_dashboard')).filter((value): value is boolean => value !== null)
  const trendKnown = reportJobs.map((job) => hasReportFeature(job, 'prioritisation_trends')).filter((value): value is boolean => value !== null)
  const fixFirstLoaded = summaries.filter((summary) => summary.has_fix_first_dashboard).length
  const trendLoaded = summaries.filter((summary) => summary.has_trend_data).length

  if (!apiOnline && !demoMode) {
    return <div className="empty-state">API offline. Evidence & Reports will load when the local API is reachable.</div>
  }

  return (
    <div className="reports-view">
      <div className="button-row button-row--right">
        <button className="secondary-button" type="button" onClick={() => void loadReports()} disabled={loading}>
          Refresh reports
        </button>
      </div>

      <div className="report-note">
        Use View or Download to access Security Finding Reports through the local authenticated API when report URLs are available. Local report paths may still need to be opened from your file explorer or terminal.
        <code>Start-Process .\reports\REPORT_FILE.html</code>
      </div>

      <div className="report-card-grid">
        <ReportCard label="Total Completed Jobs" value={jobs.length} />
        <ReportCard label="JSON Security Reports" value={jsonReports} />
        <ReportCard label="HTML Security Reports" value={htmlReports} />
        <ReportCard label="API JSON Reports Indexed" value={indexedJsonReports || null} />
        <ReportCard label="API HTML Reports Indexed" value={indexedHtmlReports || null} />
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
        onViewReport={handleViewReport}
        onDownloadReport={handleDownloadReport}
      />

      {apiReports.length ? (
        <div className="report-index-panel">
          <div className="panel-heading">
            <h2>API Security Report Index</h2>
            <p>Security Finding Reports safely served from the VulScan reports directory.</p>
          </div>
          <div className="report-index-list">
            {apiReports.slice(0, 8).map((report) => (
              <div className="report-index-item" key={report.report_id || report.filename}>
                <div>
                  <strong>{report.filename || 'Unnamed report'}</strong>
                  <span>{report.type || 'unknown'} / {report.target || 'Not available'} / {formatDateTime(report.created_at)}</span>
                </div>
                <div className="report-actions">
                  {report.type === 'html' && report.view_url ? (
                    <button className="ghost-button compact-button" type="button" onClick={() => void handleViewReport(report.view_url, report.filename)}>
                      View
                    </button>
                  ) : null}
                  {report.download_url ? (
                    <button className="ghost-button compact-button" type="button" onClick={() => void handleDownloadReport(report.download_url, report.filename)}>
                      Download
                    </button>
                  ) : null}
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : null}

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
        onViewReport={handleViewReport}
        onDownloadReport={handleDownloadReport}
      />
    </div>
  )
}
