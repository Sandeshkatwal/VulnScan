import { useCallback, useEffect, useMemo, useState } from 'react'
import { apiBaseUrl, getHealth, getJobFindings, getJobs, getScans, getVersion } from './api/client'
import { FindingSummary, buildPrioritySummary } from './components/FindingSummary'
import { JobsTable } from './components/JobsTable'
import { Layout } from './components/Layout'
import { ScansTable } from './components/ScansTable'
import { StatusCard } from './components/StatusCard'
import type { Finding, HealthResponse, JobSummary, ScanSummary, VersionResponse } from './types/api'

interface DashboardState {
  health: HealthResponse | null
  version: VersionResponse | null
  jobs: JobSummary[]
  scans: ScanSummary[]
  findings: Finding[]
  apiError: string | null
  jobsError: string | null
  scansError: string | null
  findingsError: string | null
  loading: boolean
}

const initialState: DashboardState = {
  health: null,
  version: null,
  jobs: [],
  scans: [],
  findings: [],
  apiError: null,
  jobsError: null,
  scansError: null,
  findingsError: null,
  loading: true,
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Request failed.'
}

function completedJobs(jobs: JobSummary[]): JobSummary[] {
  return jobs.filter((job) => job.status === 'completed')
}

function App() {
  const [state, setState] = useState<DashboardState>(initialState)

  const loadDashboard = useCallback(async () => {
    setState((current) => ({ ...current, loading: true }))

    const [healthResult, versionResult, jobsResult, scansResult] = await Promise.allSettled([
      getHealth(),
      getVersion(),
      getJobs(10),
      getScans(10),
    ])

    const jobs = jobsResult.status === 'fulfilled' ? jobsResult.value.jobs : []
    const latestCompletedJobs = completedJobs(jobs).slice(0, 5)
    const findingResults = await Promise.allSettled(
      latestCompletedJobs.map((job) =>
        job.job_id ? getJobFindings(job.job_id, { limit: 100, compact: true }) : Promise.resolve({ findings: [] }),
      ),
    )
    const findings = findingResults.flatMap((result) =>
      result.status === 'fulfilled' ? result.value.findings : [],
    )
    const failedFindingResult = findingResults.find((result) => result.status === 'rejected')

    setState({
      health: healthResult.status === 'fulfilled' ? healthResult.value : null,
      version: versionResult.status === 'fulfilled' ? versionResult.value : null,
      jobs,
      scans: scansResult.status === 'fulfilled' ? scansResult.value.scans : [],
      findings,
      apiError: healthResult.status === 'rejected' ? errorMessage(healthResult.reason) : null,
      jobsError: jobsResult.status === 'rejected' ? errorMessage(jobsResult.reason) : null,
      scansError: scansResult.status === 'rejected' ? errorMessage(scansResult.reason) : null,
      findingsError: failedFindingResult?.status === 'rejected' ? errorMessage(failedFindingResult.reason) : null,
      loading: false,
    })
  }, [])

  useEffect(() => {
    void loadDashboard()
  }, [loadDashboard])

  const prioritySummary = useMemo(() => buildPrioritySummary(state.findings), [state.findings])
  const completedCount = useMemo(() => completedJobs(state.jobs).length, [state.jobs])
  const failedCount = state.jobs.filter((job) => job.status === 'failed').length
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
      <section className="overview-grid" aria-label="Dashboard overview">
        <StatusCard
          label="API Health"
          value={state.health?.status || 'offline'}
          description={state.version?.api_version ? `API ${state.version.api_version}` : 'Local API status'}
          tone={healthTone}
        />
        <StatusCard label="Recent Jobs" value={state.jobs.length} description="Last 10 API jobs" />
        <StatusCard label="Completed Jobs" value={completedCount} description="Recent completed jobs" tone="good" />
        <StatusCard label="Failed Jobs" value={failedCount} description="Recent failed jobs" tone={failedCount ? 'bad' : 'neutral'} />
        <StatusCard label="Recent Scans" value={state.scans.length} description="Saved scan history" />
      </section>

      <section className="content-grid">
        <article className="panel panel--wide">
          <div className="panel-heading">
            <h2>Recent Jobs</h2>
            <p>Persistent local API scan jobs.</p>
          </div>
          <JobsTable jobs={state.jobs} loading={state.loading && state.jobs.length === 0} error={state.jobsError} />
        </article>

        <article className="panel">
          <div className="panel-heading">
            <h2>Findings / Priority Summary</h2>
            <p>Aggregated from recent completed job findings when available.</p>
          </div>
          <FindingSummary summary={prioritySummary} loading={state.loading} error={state.findingsError} />
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
          <p>Reserved for filterable finding review and remediation workflow.</p>
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
