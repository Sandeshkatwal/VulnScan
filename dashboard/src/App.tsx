import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  apiBaseUrl,
  createScan,
  getHealth,
  getJob,
  getJobFindings,
  getJobResult,
  getJobs,
  getRemediationRecord,
  getScans,
  getVersion,
  updateRemediation,
} from './api/client'
import { demoFindings, demoJobResult, demoJobs, demoRemediationRecords, demoRemediationSummary, demoScans } from './demo/demoData'
import { ApiConnectionManager } from './components/ApiConnectionManager'
import { ArchitectureSummary } from './components/ArchitectureSummary'
import { BugBountyReconView } from './components/BugBountyReconView'
import { BugBountyScopeView } from './components/BugBountyScopeView'
import { DemoModeToggle } from './components/DemoModeToggle'
import { EndpointDiscoveryView } from './components/EndpointDiscoveryView'
import { ErrorAlert } from './components/ErrorAlert'
import { FindingSummary, buildPrioritySummary } from './components/FindingSummary'
import { FindingDetailDrawer } from './components/FindingDetailDrawer'
import { JobDetails } from './components/JobDetails'
import { JobsTable, statusTone } from './components/JobsTable'
import { Layout } from './components/Layout'
import { PortfolioFooter } from './components/PortfolioFooter'
import { PortfolioModeBanner } from './components/PortfolioModeBanner'
import { ProductHero } from './components/ProductHero'
import { ReportsView } from './components/ReportsView'
import { RemediationView } from './components/RemediationView'
import { RiskOverview } from './components/RiskOverview'
import { ScansTable } from './components/ScansTable'
import { ScanJobForm } from './components/ScanJobForm'
import { SectionHeader } from './components/SectionHeader'
import { ScreenshotGuide } from './components/ScreenshotGuide'
import { StatusCard } from './components/StatusCard'
import { TrendsView } from './components/TrendsView'
import { VulnerabilityList } from './components/VulnerabilityList'
import type {
  Finding,
  FindingFilters,
  HealthResponse,
  JobResultResponse,
  JobSummary,
  Pagination,
  RemediationRecord,
  RemediationUpdatePayload,
  ScanRequest,
  ScanResponse,
  ScanSummary,
  VersionResponse,
} from './types/api'
import { DEMO_MODE_MESSAGE, envDemoMode, portfolioMode, screenshotMode } from './utils/demoMode'

type DashboardSection = 'overview' | 'jobs' | 'vulnerabilities' | 'risk' | 'trends' | 'reports' | 'remediation' | 'bug-bounty' | 'bug-bounty-recon' | 'endpoint-discovery' | 'settings'

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

const demoVersion: VersionResponse = { scanner: 'VulScan', version: '18.1-demo', api_version: '18.1' }

const defaultFindingFilters: FindingFilters = {
  limit: 20,
  offset: 0,
  sort_by: 'priority_score',
  sort_order: 'desc',
  compact: false,
}

const navigationItems: Array<{ id: DashboardSection; label: string }> = [
  { id: 'overview', label: 'Overview' },
  { id: 'jobs', label: 'Jobs' },
  { id: 'vulnerabilities', label: 'Vulnerabilities' },
  { id: 'risk', label: 'Risk' },
  { id: 'trends', label: 'Trends' },
  { id: 'reports', label: 'Reports' },
  { id: 'remediation', label: 'Remediation' },
  { id: 'bug-bounty', label: 'Bug Bounty' },
  { id: 'bug-bounty-recon', label: 'Recon' },
  { id: 'endpoint-discovery', label: 'Endpoints' },
  { id: 'settings', label: 'Settings' },
]

const sectionCopy: Record<DashboardSection, { title: string; description: string }> = {
  overview: {
    title: 'Overview',
    description: 'API status, job counts, scan history, and quick prioritisation summary.',
  },
  jobs: {
    title: 'Jobs',
    description: 'Create safe scan jobs, inspect job status, and load results or findings.',
  },
  vulnerabilities: {
    title: 'Vulnerabilities',
    description: 'Filter, sort, page, and inspect read-only findings for the selected completed job.',
  },
  risk: {
    title: 'Risk',
    description: 'Visual risk overview, distributions, and top risk findings.',
  },
  trends: {
    title: 'Trends',
    description: 'Prioritisation trend comparisons for scans with saved trend data.',
  },
  reports: {
    title: 'Reports',
    description: 'Saved JSON and HTML report paths from completed jobs.',
  },
  remediation: {
    title: 'Remediation',
    description: 'Tracking-only remediation status, owners, due dates, and notes.',
  },
  'bug-bounty': {
    title: 'Bug Bounty',
    description: 'Local program scope, rules of engagement, and safe scope validation.',
  },
  'bug-bounty-recon': {
    title: 'Bug Bounty Recon',
    description: 'Scope-aware HTTP/HTTPS metadata probing for manually provided authorised targets.',
  },
  'endpoint-discovery': {
    title: 'Endpoint Discovery',
    description: 'Safe endpoint and parameter candidate discovery for manual validation workflows.',
  },
  settings: {
    title: 'Settings',
    description: 'Local API connection checks, report access settings, and dashboard mode.',
  },
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
  const [selectedRemediation, setSelectedRemediation] = useState<RemediationRecord | null>(null)
  const [remediationLoading, setRemediationLoading] = useState(false)
  const [remediationError, setRemediationError] = useState<string | null>(null)
  const [remediationMessage, setRemediationMessage] = useState<string | null>(null)
  const [currentSection, setCurrentSection] = useState<DashboardSection>('overview')
  const [demoMode, setDemoMode] = useState(envDemoMode)

  const loadDashboard = useCallback(async () => {
    if (demoMode) {
      setState({
        health: { status: 'ok', scanner: 'VulScan Demo' },
        version: demoVersion,
        jobs: demoJobs,
        scans: demoScans,
        apiError: null,
        jobsError: null,
        scansError: null,
        loading: false,
      })
      return
    }
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
  }, [demoMode])

  useEffect(() => {
    void loadDashboard()
  }, [loadDashboard])

  const loadResult = useCallback(async () => {
    if (!selectedJob?.job_id) return
    if (demoMode) {
      setJobResult(demoJobResult)
      setResultError(null)
      return
    }
    setResultLoading(true)
    setResultError(null)
    try {
      setJobResult(await getJobResult(selectedJob.job_id))
    } catch (caught) {
      setResultError(errorMessage(caught))
    } finally {
      setResultLoading(false)
    }
  }, [demoMode, selectedJob])

  const loadRiskData = useCallback(async (job: JobSummary) => {
    if (!job.job_id || job.status !== 'completed') return
    if (demoMode) {
      setJobResult(demoJobResult)
      setRiskFindings(demoFindings)
      setRiskError(null)
      return
    }
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
  }, [demoMode])

  const loadFindings = useCallback(
    async (filters: FindingFilters = findingFilters) => {
      if (!selectedJob?.job_id) return
      if (demoMode) {
        setFindings(demoFindings)
        setFindingPagination({ limit: filters.limit || 20, offset: filters.offset || 0, returned: demoFindings.length, total: demoFindings.length })
        setFindingsError(null)
        return
      }
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
    [demoMode, findingFilters, selectedJob],
  )

  const loadSelectedJob = useCallback(
    async (jobId?: string) => {
      const id = jobId || selectedJob?.job_id
      if (!id) return
      if (demoMode) {
        setSelectedJob(demoJobs[0])
        setJobResult(demoJobResult)
        setFindings(demoFindings)
        setRiskFindings(demoFindings)
        setFindingPagination({ limit: 20, offset: 0, returned: demoFindings.length, total: demoFindings.length })
        return
      }
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
    [demoMode, loadRiskData, selectedJob],
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
      setSelectedRemediation(null)

      if (!job.job_id) return
      if (demoMode) {
        setSelectedJob(job)
        setJobResult(demoJobResult)
        setFindings(demoFindings)
        setRiskFindings(demoFindings)
        setFindingPagination({ limit: 20, offset: 0, returned: demoFindings.length, total: demoFindings.length })
        return
      }

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
    [demoMode],
  )

  useEffect(() => {
    if (selectedJob?.job_id || state.loading) return
    const latestCompleted = state.jobs.find((job) => job.status === 'completed' && job.job_id)
    if (latestCompleted) {
      void selectAndLoadJob(latestCompleted)
    }
  }, [selectAndLoadJob, selectedJob, state.jobs, state.loading])

  async function handleCreateScan(request: ScanRequest): Promise<ScanResponse> {
    if (demoMode) {
      setSelectedJob(demoJobs[0])
      setJobResult(demoJobResult)
      setFindings(demoFindings)
      setRiskFindings(demoFindings)
      setFindingPagination({ limit: 20, offset: 0, returned: demoFindings.length, total: demoFindings.length })
      return { job_id: 'demo-job-001', scan_id: 'demo-scan-001', status: 'completed', target: request.target || 'demo-web.local' }
    }
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
      setSelectedRemediation(null)
      setJobActionError(null)
      setState((current) => ({ ...current, jobs: mergeJob(current.jobs, job) }))
    }
    return response
  }

  function handleSelectJob(job: JobSummary) {
    void selectAndLoadJob(job)
  }

  async function handleSelectFinding(finding: Finding) {
    setSelectedFinding(finding)
    setSelectedRemediation(null)
    setRemediationError(null)
    setRemediationMessage(null)
    const findingKey = String(finding.finding_key || finding.remediation_fingerprint || '')
    if (!findingKey) {
      setRemediationError('Finding key is missing, remediation tracking is unavailable for this item.')
      return
    }
    setRemediationLoading(true)
    if (demoMode) {
      setSelectedRemediation(demoRemediationRecords.find((record) => record.finding_key === findingKey) || null)
      setRemediationLoading(false)
      return
    }
    try {
      const response = await getRemediationRecord(findingKey)
      setSelectedRemediation(response.record || null)
    } catch (caught) {
      setRemediationError(errorMessage(caught))
    } finally {
      setRemediationLoading(false)
    }
  }

  async function handleUpdateFindingRemediation(findingKey: string, payload: RemediationUpdatePayload) {
    setRemediationLoading(true)
    setRemediationError(null)
    setRemediationMessage(null)
    if (demoMode) {
      setSelectedRemediation((current) => current ? { ...current, ...payload, updated_at: new Date().toISOString() } : current)
      setRemediationMessage('Demo remediation tracking updated.')
      setRemediationLoading(false)
      return
    }
    try {
      const response = await updateRemediation(findingKey, payload)
      setSelectedRemediation(response.record || null)
      setRemediationMessage('Remediation tracking updated.')
      void loadFindings()
      if (selectedJob?.status === 'completed') void loadRiskData(selectedJob)
    } catch (caught) {
      setRemediationError(errorMessage(caught))
    } finally {
      setRemediationLoading(false)
    }
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
  const section = sectionCopy[currentSection]
  const selectedIndicator = selectedJob?.job_id
    ? `${selectedJob.target || 'Selected target'} / ${selectedJob.status || 'unknown'} / ${selectedJob.job_id}`
    : 'No job selected'

  const overviewCards = (
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
  )

  function renderOverview() {
    return (
      <>
        {portfolioMode ? <ProductHero /> : null}
        {demoMode ? <div className="demo-mode-callout">{DEMO_MODE_MESSAGE}</div> : null}
        {overviewCards}
        <section className="content-grid">
          {portfolioMode ? <article className="panel panel--wide"><ArchitectureSummary /></article> : null}
          {screenshotMode ? <article className="panel panel--wide"><ScreenshotGuide /></article> : null}
          <article className="panel">
            <div className="panel-heading">
              <h2>Quick Risk Summary</h2>
              <p>Selected job findings after they are loaded.</p>
            </div>
            <FindingSummary summary={prioritySummary} loading={findingsLoading} error={findingsError} />
          </article>
          <article className="panel">
            <div className="panel-heading">
              <h2>Recent Scans</h2>
              <p>Saved scan history.</p>
            </div>
            <ScansTable scans={state.scans} loading={state.loading && state.scans.length === 0} error={state.scansError} />
          </article>
          <article className="panel panel--wide">
            <div className="panel-heading">
              <h2>Recent Jobs</h2>
              <p>Select a completed job to populate vulnerabilities, risk, trends, and reports.</p>
            </div>
            <JobsTable
              jobs={state.jobs}
              loading={state.loading && state.jobs.length === 0}
              error={state.jobsError}
              selectedJobId={selectedJob?.job_id}
              onSelectJob={handleSelectJob}
            />
          </article>
        </section>
      </>
    )
  }

  function renderJobs() {
    return (
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
      </section>
    )
  }

  function renderVulnerabilities() {
    return (
      <article className="panel panel--wide">
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
          onSelectFinding={(finding) => void handleSelectFinding(finding)}
        />
      </article>
    )
  }

  function renderRisk() {
    return (
      <article className="panel panel--wide">
        <RiskOverview
          job={selectedJob}
          result={jobResult}
          findings={riskFindings}
          loading={riskLoading}
          error={riskError}
          apiOnline={healthTone !== 'bad'}
          onSelectFinding={(finding) => void handleSelectFinding(finding)}
        />
      </article>
    )
  }

  function renderTrends() {
    return (
      <article className="panel panel--wide">
        <TrendsView job={selectedJob} result={jobResult} resultLoading={resultLoading || riskLoading} resultError={resultError} />
      </article>
    )
  }

  function renderReports() {
    return (
      <article className="panel panel--wide">
        <ReportsView apiOnline={healthTone !== 'bad'} demoMode={demoMode} demoJobs={demoJobs} demoResult={demoJobResult} demoFindings={demoFindings} />
      </article>
    )
  }

  function renderRemediation() {
    return (
      <article className="panel panel--wide">
        <RemediationView apiOnline={healthTone !== 'bad'} demoMode={demoMode} demoRecords={demoRemediationRecords} demoSummary={demoRemediationSummary} />
      </article>
    )
  }

  function renderBugBounty() {
    return <BugBountyScopeView apiOnline={healthTone !== 'bad'} demoMode={demoMode} />
  }

  function renderBugBountyRecon() {
    return <BugBountyReconView apiOnline={healthTone !== 'bad'} demoMode={demoMode} />
  }

  function renderEndpointDiscovery() {
    return <EndpointDiscoveryView apiOnline={healthTone !== 'bad'} demoMode={demoMode} />
  }

  function renderSettings() {
    return (
      <section className="settings-grid">
        <article className="panel panel--wide">
          <div className="panel-heading">
            <h2>API Connection Manager</h2>
            <p>Environment-driven local settings and safe connection tests.</p>
          </div>
          <ApiConnectionManager onRefreshDashboard={() => void loadDashboard()} refreshLoading={state.loading} />
          <div className="settings-mode-grid">
            <div><span>Demo mode</span><strong>{demoMode ? 'Enabled' : 'Disabled'}</strong></div>
            <div><span>Portfolio mode</span><strong>{portfolioMode ? 'Enabled' : 'Disabled'}</strong></div>
            <div><span>Screenshot mode</span><strong>{screenshotMode ? 'Enabled' : 'Disabled'}</strong></div>
            <div><span>Local-only status</span><strong>Local development</strong></div>
          </div>
        </article>
        <article className="panel">
          <div className="panel-heading">
            <h2>Local-Only Notice</h2>
            <p>Operational boundary for this dashboard.</p>
          </div>
          <div className="empty-state">VulScan Dashboard is intended for local authorised testing and development. Do not expose it publicly.</div>
          <DemoModeToggle enabled={demoMode} envEnabled={envDemoMode} onChange={setDemoMode} />
          <div className="button-row button-row--right">
            <button className="secondary-button" type="button" onClick={() => void loadDashboard()} disabled={state.loading}>
              Refresh dashboard data
            </button>
          </div>
        </article>
      </section>
    )
  }

  function renderCurrentSection() {
    if (currentSection === 'overview') return renderOverview()
    if (currentSection === 'jobs') return renderJobs()
    if (currentSection === 'vulnerabilities') return renderVulnerabilities()
    if (currentSection === 'risk') return renderRisk()
    if (currentSection === 'trends') return renderTrends()
    if (currentSection === 'reports') return renderReports()
    if (currentSection === 'remediation') return renderRemediation()
    if (currentSection === 'bug-bounty') return renderBugBounty()
    if (currentSection === 'bug-bounty-recon') return renderBugBountyRecon()
    if (currentSection === 'endpoint-discovery') return renderEndpointDiscovery()
    return renderSettings()
  }

  return (
    <Layout
      activeSection={currentSection}
      apiBaseUrl={apiBaseUrl}
      health={state.health}
      version={state.version}
      apiError={state.apiError}
      loading={state.loading}
      navigationItems={navigationItems}
      selectedIndicator={selectedIndicator}
      title={section.title}
      onRefresh={loadDashboard}
      onSelectSection={(nextSection) => setCurrentSection(nextSection as DashboardSection)}
    >
      <SectionHeader title={section.title} description={section.description} />
      <PortfolioModeBanner demoMode={demoMode} portfolioMode={portfolioMode} />
      {renderCurrentSection()}
      <FindingDetailDrawer
        finding={selectedFinding}
        remediationRecord={selectedRemediation}
        remediationLoading={remediationLoading}
        remediationError={remediationError}
        remediationMessage={remediationMessage}
        onUpdateRemediation={handleUpdateFindingRemediation}
        onClose={() => setSelectedFinding(null)}
      />
      <PortfolioFooter />
    </Layout>
  )
}

export default App
