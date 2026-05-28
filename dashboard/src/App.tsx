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
import { FindingSummary, buildPrioritySummary } from './components/FindingSummary'
import { FindingDetailDrawer } from './components/FindingDetailDrawer'
import { JobDetails } from './components/JobDetails'
import { JobsTable, statusTone } from './components/JobsTable'
import { Layout } from './components/Layout'
import { RiskOverview } from './components/RiskOverview'
import { ScansTable } from './components/ScansTable'
import { ScanJobForm } from './components/ScanJobForm'
import { StatusCard } from './components/StatusCard'
import { VulnerabilityList } from './components/VulnerabilityList'
import type {
  Finding,
  FindingFilters,
  HealthResponse,
  JobResultResponse,
  JobSummary,
  Pagination,
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
  limit: 20,
  offset: 0,
  sort_by: 'priority_score',
  sort_order: 'desc',
  compact: false,
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
  const [riskFindings, setRiskFindings] = useState<Finding[]>([])
  const [riskLoading, setRiskLoading] = useState(false)
  const [riskError, setRiskError] = useState<string | null>(null)
  const [findingFilters, setFindingFilters] = useState<FindingFilters>(defaultFindingFilters)
  const [findingPagination, setFindingPagination] = useState<Pagination | null>(null)
  const [findingsLoading, setFindingsLoading] = useState(false)
  const [findingsError, setFindingsError] = useState<string | null>(null)
  const [jobActionError, setJobActionError] = useState<string | null>(null)
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)

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

  const loadRiskData = useCallback(async (job: JobSummary) => {
    if (!job.job_id || job.status !== 'completed') return
    setRiskLoading(true)
    setRiskError(null)
    try {
      const [resultResponse, findingsResponse] = await Promise.all([
        getJobResult(job.job_id),
        getJobFindings(job.job_id, {
          limit: 500,
          offset: 0,
          sort_by: 'priority_score',
          sort_order: 'desc',
          compact: false,
        }),
      ])
      setJobResult(resultResponse)
      setRiskFindings(findingsResponse.findings)
      if (findingsResponse.message) {
        setRiskError(findingsResponse.message)
      }
    } catch (caught) {
      setRiskError(errorMessage(caught))
    } finally {
      setRiskLoading(false)
    }
  }, [])

  const loadFindings = useCallback(
    async (filters: FindingFilters = findingFilters) => {
      if (!selectedJob?.job_id) return
      setFindingsLoading(true)
      setFindingsError(null)
      try {
        const response = await getJobFindings(selectedJob.job_id, {
          ...filters,
          limit: filters.limit || 20,
          offset: filters.offset || 0,
          sort_by: filters.sort_by || 'priority_score',
          sort_order: filters.sort_order || 'desc',
          compact: false,
        })
        setFindings(response.findings)
        setFindingPagination(response.pagination || null)
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

  const loadSelectedJob = useCallback(
    async (jobId?: string) => {
      const id = jobId || selectedJob?.job_id
      if (!id) return
      setJobActionError(null)
      try {
        const job = await getJob(id)
        setSelectedJob(job)
        setState((current) => ({ ...current, jobs: mergeJob(current.jobs, job) }))
        if (job.status === 'completed') {
          setFindingsLoading(true)
          try {
            await Promise.all([
              loadRiskData(job),
              getJobFindings(id, defaultFindingFilters).then((response) => {
                setFindings(response.findings)
                setFindingPagination(response.pagination || null)
                setFindingFilters(defaultFindingFilters)
                if (response.message) setFindingsError(response.message)
              }),
            ])
          } finally {
            setFindingsLoading(false)
          }
        }
      } catch (caught) {
        setJobActionError(errorMessage(caught))
      }
    },
    [loadRiskData, selectedJob],
  )

  const selectAndLoadJob = useCallback(
    async (job: JobSummary) => {
      setSelectedJob(job)
      setJobResult(null)
      setResultError(null)
      setFindings([])
      setRiskFindings([])
      setFindingPagination(null)
      setFindingsError(null)
      setRiskError(null)
      setJobActionError(null)
      setSelectedFinding(null)

      if (!job.job_id) return

      try {
        setRiskLoading(true)
        setFindingsLoading(true)
        const latestJob = await getJob(job.job_id)
        setSelectedJob(latestJob)
        setState((current) => ({ ...current, jobs: mergeJob(current.jobs, latestJob) }))
        if (latestJob.status !== 'completed') {
          return
        }
        const latestJobId = latestJob.job_id
        if (!latestJobId) return

        const [resultResponse, listFindingsResponse, riskFindingsResponse] = await Promise.all([
          getJobResult(latestJobId),
          getJobFindings(latestJobId, defaultFindingFilters),
          getJobFindings(latestJobId, {
            limit: 500,
            offset: 0,
            sort_by: 'priority_score',
            sort_order: 'desc',
            compact: false,
          }),
        ])
        setJobResult(resultResponse)
        setFindings(listFindingsResponse.findings)
        setFindingPagination(listFindingsResponse.pagination || null)
        setRiskFindings(riskFindingsResponse.findings)
        setFindingFilters(defaultFindingFilters)
        if (listFindingsResponse.message) setFindingsError(listFindingsResponse.message)
        if (riskFindingsResponse.message) setRiskError(riskFindingsResponse.message)
      } catch (caught) {
        const message = errorMessage(caught)
        setJobActionError(message)
        setRiskError(message)
      } finally {
        setRiskLoading(false)
        setFindingsLoading(false)
      }
    },
    [],
  )

  useEffect(() => {
    if (selectedJob?.job_id || state.loading) return
    const latestCompleted = state.jobs.find((job) => job.status === 'completed' && job.job_id)
    if (latestCompleted) {
      void selectAndLoadJob(latestCompleted)
    }
  }, [selectAndLoadJob, selectedJob, state.jobs, state.loading])

  async function handleCreateScan(request: ScanRequest): Promise<ScanResponse> {
    const response = await createScan(request)
    await loadDashboard()
    if (response.job_id) {
      const job = await getJob(response.job_id)
      setSelectedJob(job)
      setJobResult(null)
      setFindings([])
      setRiskFindings([])
      setFindingPagination(null)
      setRiskError(null)
      setFindingsError(null)
      setSelectedFinding(null)
      setJobActionError(null)
      setState((current) => ({ ...current, jobs: mergeJob(current.jobs, job) }))
    }
    return response
  }

  function handleSelectJob(job: JobSummary) {
    void selectAndLoadJob(job)
  }

  function clearFilters() {
    setFindingFilters(defaultFindingFilters)
    void loadFindings(defaultFindingFilters)
  }

  function updateFindingPage(limit: number, offset: number) {
    const nextFilters = { ...findingFilters, limit, offset }
    setFindingFilters(nextFilters)
    void loadFindings(nextFilters)
  }

  function applyFindingFilters() {
    const nextFilters = { ...findingFilters, offset: 0 }
    setFindingFilters(nextFilters)
    void loadFindings(nextFilters)
  }

  function updateFindingSort(sortBy: string) {
    const currentOrder = findingFilters.sort_by === sortBy ? findingFilters.sort_order : 'desc'
    const nextOrder = currentOrder === 'asc' ? 'desc' : 'asc'
    const nextFilters = { ...findingFilters, sort_by: sortBy, sort_order: nextOrder, offset: 0 }
    setFindingFilters(nextFilters)
    void loadFindings(nextFilters)
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
            <h2>Risk Overview</h2>
            <p>Visual risk summary for the selected completed job.</p>
          </div>
          <RiskOverview
            job={selectedJob}
            result={jobResult}
            findings={riskFindings}
            loading={riskLoading}
            error={riskError}
            apiOnline={healthTone !== 'bad'}
            onSelectFinding={setSelectedFinding}
          />
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
            <h2>Vulnerability List</h2>
            <p>Read-only findings for the selected completed job.</p>
          </div>
          <VulnerabilityList
            findings={findings}
            filters={findingFilters}
            pagination={findingPagination}
            loading={findingsLoading}
            error={findingsError}
            selectedJobStatus={selectedJob?.status}
            hasSelectedJob={Boolean(selectedJob?.job_id)}
            onFiltersChange={setFindingFilters}
            onApplyFilters={applyFindingFilters}
            onClearFilters={clearFilters}
            onPageChange={updateFindingPage}
            onSort={updateFindingSort}
            onRefresh={() => void loadFindings()}
            onSelectFinding={setSelectedFinding}
          />
        </article>

        <article className="panel panel--wide">
          <div className="panel-heading">
            <h2>Recent Scans</h2>
            <p>Saved SQLite scan history.</p>
          </div>
          <ScansTable scans={state.scans} loading={state.loading && state.scans.length === 0} error={state.scansError} />
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
      <FindingDetailDrawer finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
    </Layout>
  )
}

export default App
