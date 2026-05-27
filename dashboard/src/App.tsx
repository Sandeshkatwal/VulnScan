import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  apiBaseUrl,
  createScan,
  getHealth,
  getJob,
  getJobFindings,
  getJobResult,
  getJobs,
  getScans,
  getVersion,
} from './api/client'
import { ErrorAlert } from './components/ErrorAlert'
import { FilterBar } from './components/FilterBar'
import { FindingSummary, buildPrioritySummary } from './components/FindingSummary'
import { FindingsTable } from './components/FindingsTable'
import { JobDetails } from './components/JobDetails'
import { JobsTable, statusTone } from './components/JobsTable'
import { Layout } from './components/Layout'
import { ScansTable } from './components/ScansTable'
import { ScanJobForm } from './components/ScanJobForm'
import { StatusCard } from './components/StatusCard'
import type {
  Finding,
  FindingFilters,
  HealthResponse,
  JobResultResponse,
  JobSummary,
  ScanRequest,
  ScanResponse,
  ScanSummary,
  VersionResponse,
} from './types/api'

interface DashboardState {
  health: HealthResponse | null
  version: VersionResponse | null
  jobs: JobSummary[]
  scans: ScanSummary[]
  apiError: string | null
  jobsError: string | null
  scansError: string | null
  loading: boolean
}

const initialState: DashboardState = {
  health: null,
  version: null,
  jobs: [],
  scans: [],
  apiError: null,
  jobsError: null,
  scansError: null,
  loading: true,
}

const defaultFindingFilters: FindingFilters = {
  limit: 100,
  compact: true,
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Request failed.'
}

function countJobs(jobs: JobSummary[], status: string): number {
  return jobs.filter((job) => job.status === status).length
}

function mergeJob(jobs: JobSummary[], selected: JobSummary): JobSummary[] {
  return jobs.map((job) => (job.job_id === selected.job_id ? selected : job))
}

function App() {
  const [state, setState] = useState<DashboardState>(initialState)
  const [selectedJob, setSelectedJob] = useState<JobSummary | null>(null)
  const [jobResult, setJobResult] = useState<JobResultResponse | null>(null)
  const [resultLoading, setResultLoading] = useState(false)
  const [resultError, setResultError] = useState<string | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [findingFilters, setFindingFilters] = useState<FindingFilters>(defaultFindingFilters)
  const [findingsLoading, setFindingsLoading] = useState(false)
  const [findingsError, setFindingsError] = useState<string | null>(null)
  const [jobActionError, setJobActionError] = useState<string | null>(null)

  const loadDashboard = useCallback(async () => {
    setState((current) => ({ ...current, loading: true }))

    const [healthResult, versionResult, jobsResult, scansResult] = await Promise.allSettled([
      getHealth(),
      getVersion(),
      getJobs({ limit: 10 }),
      getScans({ limit: 10 }),
    ])

    const jobs = jobsResult.status === 'fulfilled' ? jobsResult.value.jobs : []
    setState({
      health: healthResult.status === 'fulfilled' ? healthResult.value : null,
      version: versionResult.status === 'fulfilled' ? versionResult.value : null,
      jobs,
      scans: scansResult.status === 'fulfilled' ? scansResult.value.scans : [],
      apiError: healthResult.status === 'rejected' ? errorMessage(healthResult.reason) : null,
      jobsError: jobsResult.status === 'rejected' ? errorMessage(jobsResult.reason) : null,
      scansError: scansResult.status === 'rejected' ? errorMessage(scansResult.reason) : null,
      loading: false,
    })

    setSelectedJob((current) => {
      if (!current?.job_id) return current
      return jobs.find((job) => job.job_id === current.job_id) || current
    })
  }, [])

  useEffect(() => {
    void loadDashboard()
  }, [loadDashboard])

  const loadSelectedJob = useCallback(
    async (jobId?: string) => {
      const id = jobId || selectedJob?.job_id
      if (!id) return
      setJobActionError(null)
      try {
        const job = await getJob(id)
        setSelectedJob(job)
        setState((current) => ({ ...current, jobs: mergeJob(current.jobs, job) }))
      } catch (caught) {
        setJobActionError(errorMessage(caught))
      }
    },
    [selectedJob],
  )

  const loadResult = useCallback(async () => {
    if (!selectedJob?.job_id) return
    setResultLoading(true)
    setResultError(null)
    try {
      setJobResult(await getJobResult(selectedJob.job_id))
    } catch (caught) {
      setResultError(errorMessage(caught))
    } finally {
      setResultLoading(false)
    }
  }, [selectedJob])

  const loadFindings = useCallback(
    async (filters: FindingFilters = findingFilters) => {
      if (!selectedJob?.job_id) return
      setFindingsLoading(true)
      setFindingsError(null)
      try {
        const response = await getJobFindings(selectedJob.job_id, {
          ...filters,
          limit: filters.limit || 100,
          compact: true,
        })
        setFindings(response.findings)
        if (response.message) {
          setFindingsError(response.message)
        }
      } catch (caught) {
        setFindingsError(errorMessage(caught))
      } finally {
        setFindingsLoading(false)
      }
    },
    [findingFilters, selectedJob],
  )

  async function handleCreateScan(request: ScanRequest): Promise<ScanResponse> {
    const response = await createScan(request)
    await loadDashboard()
    if (response.job_id) {
      const job = await getJob(response.job_id)
      setSelectedJob(job)
      setJobResult(null)
      setFindings([])
      setJobActionError(null)
      setState((current) => ({ ...current, jobs: mergeJob(current.jobs, job) }))
    }
    return response
  }

  function handleSelectJob(job: JobSummary) {
    setSelectedJob(job)
    setJobResult(null)
    setResultError(null)
    setFindings([])
    setFindingsError(null)
    setJobActionError(null)
  }

  function clearFilters() {
    setFindingFilters(defaultFindingFilters)
    void loadFindings(defaultFindingFilters)
  }

  const prioritySummary = useMemo(() => buildPrioritySummary(findings), [findings])
  const queuedCount = countJobs(state.jobs, 'queued')
  const runningCount = countJobs(state.jobs, 'running')
  const completedCount = countJobs(state.jobs, 'completed')
  const failedCount = countJobs(state.jobs, 'failed')
  const healthTone = state.health?.status === 'ok' && !state.apiError ? 'good' : 'bad'

  return (
    <Layout
      apiBaseUrl={apiBaseUrl}
      health={state.health}
      version={state.version}
      apiError={state.apiError}
      loading={state.loading}
      onRefresh={loadDashboard}
    >
      <section className="overview-grid overview-grid--six" aria-label="Dashboard overview">
        <StatusCard
          label="API Health"
          value={state.health?.status || 'offline'}
          description={state.version?.api_version ? `API ${state.version.api_version}` : 'Local API status'}
          tone={healthTone}
        />
        <StatusCard label="Recent Jobs" value={state.jobs.length} description="Last 10 API jobs" />
        <StatusCard label="Queued" value={queuedCount} description="Waiting jobs" tone={queuedCount ? 'warn' : 'neutral'} />
        <StatusCard label="Running" value={runningCount} description="Active jobs" tone={runningCount ? 'warn' : 'neutral'} />
        <StatusCard label="Completed" value={completedCount} description="Recent completed jobs" tone="good" />
        <StatusCard label="Failed" value={failedCount} description="Recent failed jobs" tone={failedCount ? 'bad' : 'neutral'} />
        <StatusCard
          label="Selected Job"
          value={selectedJob?.status || 'none'}
          description={selectedJob?.job_id || 'No job selected'}
          tone={statusTone(selectedJob?.status) as 'neutral' | 'good' | 'warn' | 'bad'}
        />
        <StatusCard label="Recent Scans" value={state.scans.length} description="Saved scan history" />
      </section>

      <section className="content-grid">
        <article className="panel">
          <div className="panel-heading">
            <h2>Create Safe Scan Job</h2>
            <p>Starts a safe API scan job only.</p>
          </div>
          <ScanJobForm onSubmit={handleCreateScan} />
        </article>

        <article className="panel">
          <div className="panel-heading">
            <h2>Findings / Priority Summary</h2>
            <p>Summarises selected job findings after loading them.</p>
          </div>
          <FindingSummary summary={prioritySummary} loading={findingsLoading} error={findingsError} />
        </article>

        <article className="panel panel--wide">
          <div className="panel-heading">
            <h2>Recent Jobs</h2>
            <p>Click a row to inspect status, result, and findings.</p>
          </div>
          <JobsTable
            jobs={state.jobs}
            loading={state.loading && state.jobs.length === 0}
            error={state.jobsError}
            selectedJobId={selectedJob?.job_id}
            onSelectJob={handleSelectJob}
          />
        </article>

        <article className="panel">
          <div className="panel-heading">
            <h2>Job Details</h2>
            <p>Status and result metadata for the selected job.</p>
          </div>
          <ErrorAlert message={jobActionError} />
          <JobDetails
            job={selectedJob}
            result={jobResult}
            resultLoading={resultLoading}
            resultError={resultError}
            onRefreshJob={() => void loadSelectedJob()}
            onLoadResult={() => void loadResult()}
            onLoadFindings={() => void loadFindings()}
          />
        </article>

        <article className="panel panel--wide">
          <div className="panel-heading">
            <h2>Job Findings</h2>
            <p>Filtered findings from the selected completed job.</p>
          </div>
          <FilterBar
            filters={findingFilters}
            onChange={setFindingFilters}
            onApply={() => void loadFindings()}
            onClear={clearFilters}
            disabled={!selectedJob?.job_id || selectedJob.status !== 'completed' || findingsLoading}
          />
          <div className="button-row button-row--right">
            <button
              className="secondary-button"
              type="button"
              disabled={!selectedJob?.job_id || selectedJob.status !== 'completed' || findingsLoading}
              onClick={() => void loadFindings()}
            >
              Refresh findings
            </button>
          </div>
          <FindingsTable findings={findings} loading={findingsLoading} error={findingsError} />
        </article>

        <article className="panel panel--wide">
          <div className="panel-heading">
            <h2>Recent Scans</h2>
            <p>Saved SQLite scan history.</p>
          </div>
          <ScansTable scans={state.scans} loading={state.loading && state.scans.length === 0} error={state.scansError} />
        </article>

        <article className="panel placeholder-panel">
          <h2>Risk Overview</h2>
          <p>Reserved for Version 16.x risk scoring and asset context visuals.</p>
        </article>
        <article className="panel placeholder-panel">
          <h2>Vulnerability List</h2>
          <p>Reserved for wider finding review and remediation workflow.</p>
        </article>
        <article className="panel placeholder-panel">
          <h2>Trends</h2>
          <p>Reserved for prioritisation and remediation trend tracking.</p>
        </article>
        <article className="panel placeholder-panel">
          <h2>Reports</h2>
          <p>Reserved for local JSON, HTML, and export views.</p>
        </article>
      </section>
    </Layout>
  )
}

export default App
