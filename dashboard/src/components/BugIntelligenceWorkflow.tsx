import { useEffect, useMemo, useState } from 'react'
import type { CSSProperties } from 'react'
import {
  getBugBountyReconResults,
  getBugBountyScopes,
  getEndpointReports,
  getReports,
  getRetests,
  getSubmissionSummary,
  getSubmissions,
} from '../api/client'
import type {
  JobResultResponse,
  RetestRecord,
  SubmissionRecord,
  SubmissionSummary,
  WorkflowStep,
  WorkflowSummary,
  WorkflowTimelineEvent,
} from '../types/api'
import { buildNextBestActions, buildReadiness, buildWorkflowSteps, buildWorkflowSummary, buildWorkflowTimeline } from '../utils/workflowMetrics'
import { ErrorAlert } from './ErrorAlert'
import { WorkflowStatusBadge } from './WorkflowStatusBadge'

interface BugIntelligenceWorkflowProps {
  apiOnline: boolean
  demoMode?: boolean
  jobResult?: JobResultResponse | null
  onNavigate: (sectionId: string) => void
}

interface WorkflowData {
  scopesCount: number
  reconReportsCount: number
  liveAssets: number
  endpointReportsCount: number
  highInterestEndpoints: number
  owaspIndicators: number
  safeValidationResults: number
  safeValidationIndicators: number
  evidenceRecords: number
  reportDrafts: number
  submissions: SubmissionRecord[]
  retests: RetestRecord[]
}

const demoSubmissions: SubmissionRecord[] = [
  { submission_id: 'sub_demo', report_id: 'report_demo', finding_title: 'Demo Security Finding', program_name: 'Demo Program', platform: 'manual', status: 'submitted', updated_at: 'demo-local' },
]
const demoRetests: RetestRecord[] = [{ retest_id: 'retest_demo', submission_id: 'sub_demo', status: 'retest_required', updated_at: 'demo-local' }]

const demoData: WorkflowData = {
  scopesCount: 1,
  reconReportsCount: 1,
  liveAssets: 4,
  endpointReportsCount: 1,
  highInterestEndpoints: 12,
  owaspIndicators: 6,
  safeValidationResults: 3,
  safeValidationIndicators: 3,
  evidenceRecords: 3,
  reportDrafts: 2,
  submissions: demoSubmissions,
  retests: demoRetests,
}

function emptyData(): WorkflowData {
  return {
    scopesCount: 0,
    reconReportsCount: 0,
    liveAssets: 0,
    endpointReportsCount: 0,
    highInterestEndpoints: 0,
    owaspIndicators: 0,
    safeValidationResults: 0,
    safeValidationIndicators: 0,
    evidenceRecords: 0,
    reportDrafts: 0,
    submissions: [],
    retests: [],
  }
}

function jobMetric(jobResult: JobResultResponse | null | undefined, key: string): number {
  const value = jobResult?.[key]
  if (Array.isArray(value)) return value.length
  if (value && typeof value === 'object' && 'enabled' in value) return 1
  return 0
}

function owaspCount(jobResult: JobResultResponse | null | undefined): number {
  const summary = jobResult?.owasp_top10_summary as { category_counts?: Record<string, number> } | undefined
  if (!summary || typeof summary !== 'object') return 0
  const counts = summary.category_counts
  if (!counts) return 0
  return Object.values(counts).reduce<number>((total, value) => total + Number(value || 0), 0)
}

function safeValidationIndicators(jobResult: JobResultResponse | null | undefined): number {
  const summary = jobResult?.safe_active_validation as { indicators_found?: number } | undefined
  if (summary && typeof summary === 'object') return Number(summary.indicators_found || 0)
  return 0
}

function evidenceCount(jobResult: JobResultResponse | null | undefined): number {
  const findings = Array.isArray(jobResult?.findings) ? jobResult.findings : []
  return findings.filter((finding) => finding.evidence || finding.evidence_details).length
}

function summaryItems(summary: WorkflowSummary): Array<[string, number | string | undefined]> {
  return [
    ['In-scope programs', summary.inScopePrograms],
    ['Live assets discovered', summary.liveAssets],
    ['High-interest endpoints', summary.highInterestEndpoints],
    ['OWASP indicators', summary.owaspIndicators],
    ['Safe validation indicators', summary.safeValidationIndicators],
    ['Evidence records', summary.evidenceRecords],
    ['Draft reports', summary.draftReports],
    ['Submitted findings', summary.submittedFindings],
    ['Retests required', summary.retestsRequired],
    ['Accepted findings', summary.acceptedFindings],
    ['Paid findings', summary.paidFindings],
  ]
}

export function BugIntelligenceWorkflow({ apiOnline, demoMode = false, jobResult, onNavigate }: BugIntelligenceWorkflowProps) {
  const [data, setData] = useState<WorkflowData>(demoMode ? demoData : emptyData())
  const [submissionSummary, setSubmissionSummary] = useState<SubmissionSummary | null>(demoMode ? { total_count: 1, submitted_count: 1, retest_required_count: 1 } : null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (demoMode) {
      setData(demoData)
      return
    }
    if (!apiOnline) return
    setLoading(true)
    setError(null)
    Promise.allSettled([
      getBugBountyScopes(),
      getBugBountyReconResults(),
      getEndpointReports(),
      getReports({ limit: 50, type: 'all' }),
      getSubmissions(),
      getRetests(),
      getSubmissionSummary(),
    ]).then((results) => {
      const [scopes, recon, endpointReports, reports, submissions, retests, summary] = results
      const next = emptyData()
      if (scopes.status === 'fulfilled') next.scopesCount = scopes.value.scopes.length
      if (recon.status === 'fulfilled') {
        next.reconReportsCount = recon.value.reports.length
        next.liveAssets = recon.value.reports.reduce((total, item) => total + Number(item.live_count || 0), 0)
      }
      if (endpointReports.status === 'fulfilled') {
        next.endpointReportsCount = endpointReports.value.reports.length
        next.highInterestEndpoints = endpointReports.value.reports.reduce((total, item) => total + Number(item.high_interest_count || 0), 0)
      }
      if (reports.status === 'fulfilled') next.reportDrafts = reports.value.reports.length
      if (submissions.status === 'fulfilled') next.submissions = submissions.value.submissions
      if (retests.status === 'fulfilled') next.retests = retests.value.retests
      if (summary.status === 'fulfilled') setSubmissionSummary(summary.value)
      setData(next)
      const failed = results.find((result) => result.status === 'rejected')
      if (failed?.status === 'rejected') setError(failed.reason instanceof Error ? failed.reason.message : 'Some workflow data could not be loaded.')
    }).finally(() => setLoading(false))
  }, [apiOnline, demoMode])

  const merged = useMemo<WorkflowData>(() => ({
    ...data,
    owaspIndicators: Math.max(data.owaspIndicators, owaspCount(jobResult)),
    safeValidationResults: Math.max(data.safeValidationResults, jobMetric(jobResult, 'safe_active_validation_results')),
    safeValidationIndicators: Math.max(data.safeValidationIndicators, safeValidationIndicators(jobResult)),
    evidenceRecords: Math.max(data.evidenceRecords, evidenceCount(jobResult)),
  }), [data, jobResult])

  const steps = buildWorkflowSteps(merged)
  const workflowSummary = buildWorkflowSummary(merged)
  const readiness = buildReadiness(merged)
  const actions = buildNextBestActions(steps)
  const timeline = buildWorkflowTimeline(merged)

  return (
    <section className="workflow-shell">
      <article className="workflow-safety">
        <strong>Bug Intelligence workflow supports authorised testing, responsible disclosure, and internal security review.</strong>
        <span> It does not perform exploitation or automatic submission.</span>
        {demoMode ? <em> Demo data only.</em> : null}
      </article>
      <ErrorAlert message={error} />
      {!apiOnline && !demoMode ? <div className="empty-state">API offline. Workflow metrics will load when the local API is reachable.</div> : null}

      <div className="workflow-top-grid">
        <article className="workflow-readiness-card">
          <div>
            <span>Workflow readiness</span>
            <strong>{readiness.score}</strong>
            <p>{readiness.label}</p>
          </div>
          <div className="workflow-readiness-ring" style={{ '--score': readiness.score } as CSSProperties} aria-label={`Workflow readiness score ${readiness.score}`}>
            <span>{readiness.score}%</span>
          </div>
          <small>Readiness score is a workflow indicator, not a guarantee of valid vulnerability.</small>
        </article>
        <article className="workflow-actions">
          <div className="panel-heading"><h2>Next Best Actions</h2><p>{loading ? 'Refreshing workflow data...' : 'Recommended workflow movement.'}</p></div>
          {actions.map((action) => (
            <button key={action.label} className="workflow-action-button" type="button" onClick={() => action.sectionId && onNavigate(action.sectionId)}>
              <span>{action.label}</span>
              <small>{action.reason}</small>
            </button>
          ))}
        </article>
      </div>

      <article className="workflow-summary-grid">
        {summaryItems(workflowSummary).map(([label, value]) => (
          <div key={label} className="workflow-summary-card">
            <span>{label}</span>
            <strong>{value ?? 'Not available'}</strong>
          </div>
        ))}
      </article>

      <article className="workflow-stepper">
        {steps.map((step, index) => (
          <WorkflowStepCard key={step.id} step={step} index={index + 1} onNavigate={onNavigate} />
        ))}
      </article>

      <div className="workflow-bottom-grid">
        <WorkflowTimeline events={timeline} />
        <WorkflowQuickLinks steps={steps} onNavigate={onNavigate} />
      </div>
      {submissionSummary ? <div className="workflow-footnote">Submission records: {submissionSummary.total_count || 0}. Retests required: {submissionSummary.retest_required_count || 0}.</div> : null}
    </section>
  )
}

function WorkflowStepCard({ step, index, onNavigate }: { step: WorkflowStep; index: number; onNavigate: (sectionId: string) => void }) {
  return (
    <div className={`workflow-step-card workflow-step-card--${step.status.toLowerCase().replace(/\s+/g, '-')}`}>
      <div className="workflow-step-index">{index}</div>
      <div>
        <div className="workflow-step-heading"><h3>{step.label}</h3><WorkflowStatusBadge status={step.status} /></div>
        <p>{step.nextAction}</p>
        <small>{step.count ?? 0} tracked</small>
      </div>
      <button className="ghost-button compact-button" type="button" onClick={() => step.sectionId && onNavigate(step.sectionId)}>Open</button>
    </div>
  )
}

function WorkflowTimeline({ events }: { events: WorkflowTimelineEvent[] }) {
  return (
    <article className="workflow-timeline">
      <div className="panel-heading"><h2>Workflow Timeline</h2><p>Latest derived workflow events.</p></div>
      {events.length ? events.map((event) => (
        <div className="workflow-timeline-row" key={`${event.source}-${event.title}-${event.event_time}`}>
          <span>{event.event_time}</span>
          <strong>{event.event_type}</strong>
          <p>{event.title}</p>
          <small>{event.source}</small>
        </div>
      )) : <div className="empty-state">Start by creating or selecting a program scope.</div>}
    </article>
  )
}

function WorkflowQuickLinks({ steps, onNavigate }: { steps: WorkflowStep[]; onNavigate: (sectionId: string) => void }) {
  const unique = Array.from(new Map(steps.filter((step) => step.sectionId).map((step) => [step.sectionId, step])).values())
  return (
    <article className="workflow-quick-links">
      <div className="panel-heading"><h2>Quick Links</h2><p>Jump to related workflow sections.</p></div>
      <div className="workflow-link-grid">
        {unique.map((step) => <button key={step.id} className="secondary-button" type="button" onClick={() => step.sectionId && onNavigate(step.sectionId)}>Open {step.label}</button>)}
      </div>
    </article>
  )
}
