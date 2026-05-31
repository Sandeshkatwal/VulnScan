import type {
  JobResultResponse,
  NextBestAction,
  RetestRecord,
  SubmissionRecord,
  WorkflowReadiness,
  WorkflowStep,
  WorkflowSummary,
  WorkflowTimelineEvent,
} from '../types/api'

interface WorkflowInputs {
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
  jobResult?: JobResultResponse | null
}

function hasSubmitted(submissions: SubmissionRecord[]): boolean {
  return submissions.some((item) => ['submitted', 'triaged', 'accepted', 'duplicate', 'resolved', 'paid'].includes(String(item.status || '')))
}

export function buildWorkflowSummary(inputs: WorkflowInputs): WorkflowSummary {
  return {
    inScopePrograms: inputs.scopesCount,
    liveAssets: inputs.liveAssets,
    highInterestEndpoints: inputs.highInterestEndpoints,
    owaspIndicators: inputs.owaspIndicators,
    safeValidationIndicators: inputs.safeValidationIndicators,
    evidenceRecords: inputs.evidenceRecords,
    draftReports: inputs.reportDrafts,
    submittedFindings: inputs.submissions.filter((item) => ['submitted', 'triaged'].includes(String(item.status || ''))).length,
    retestsRequired: inputs.retests.filter((item) => item.status === 'retest_required').length,
    acceptedFindings: inputs.submissions.filter((item) => item.status === 'accepted').length,
    paidFindings: inputs.submissions.filter((item) => item.status === 'paid').length,
  }
}

export function buildReadiness(inputs: WorkflowInputs): WorkflowReadiness {
  let score = 0
  if (inputs.scopesCount > 0) score += 15
  if (inputs.reconReportsCount > 0 || inputs.liveAssets > 0) score += 10
  if (inputs.endpointReportsCount > 0 || inputs.highInterestEndpoints > 0) score += 10
  if (inputs.owaspIndicators > 0) score += 10
  if (inputs.safeValidationResults > 0) score += 10
  if (inputs.evidenceRecords > 0) score += 15
  if (inputs.reportDrafts > 0) score += 15
  if (inputs.submissions.length > 0) score += 10
  if (inputs.retests.length > 0 || inputs.submissions.length === 0 || !inputs.submissions.some((item) => ['accepted', 'resolved'].includes(String(item.status || '')))) score += 5
  return { score: Math.min(score, 100), label: readinessLabel(score) }
}

export function readinessLabel(score: number): string {
  if (score <= 25) return 'Getting Started'
  if (score <= 50) return 'Recon Ready'
  if (score <= 75) return 'Evidence Building'
  return 'Submission Ready'
}

export function buildWorkflowSteps(inputs: WorkflowInputs): WorkflowStep[] {
  const acceptedOrResolved = inputs.submissions.some((item) => ['accepted', 'resolved'].includes(String(item.status || '')))
  return [
    step('program-scope', 'Program Scope', inputs.scopesCount > 0 ? 'Completed' : 'Not started', inputs.scopesCount, 'Validate target against scope', 'bug-bounty'),
    step('recon', 'Recon', inputs.reconReportsCount > 0 || inputs.liveAssets > 0 ? 'Completed' : inputs.scopesCount > 0 ? 'Ready' : 'Not started', inputs.liveAssets, 'Review live assets', 'bug-bounty-recon'),
    step('endpoints', 'Endpoints', inputs.endpointReportsCount > 0 || inputs.highInterestEndpoints > 0 ? 'Completed' : inputs.reconReportsCount > 0 ? 'Ready' : 'Not started', inputs.highInterestEndpoints, 'Review high-interest parameters', 'endpoint-discovery'),
    step('owasp', 'OWASP Mapping', inputs.owaspIndicators > 0 ? 'Completed' : inputs.highInterestEndpoints > 0 ? 'Ready' : 'Not started', inputs.owaspIndicators, 'Review mapped indicators', 'owasp'),
    step('safe-validation', 'Safe Validation', inputs.safeValidationIndicators > 0 ? 'Needs review' : inputs.safeValidationResults > 0 ? 'Completed' : inputs.highInterestEndpoints > 0 ? 'Ready' : 'Not started', inputs.safeValidationIndicators, 'Convert strong indicators to evidence', 'safe-validation'),
    step('evidence', 'Evidence', inputs.evidenceRecords > 0 ? 'In progress' : inputs.safeValidationIndicators > 0 ? 'Ready' : 'Not started', inputs.evidenceRecords, 'Generate report', 'reports'),
    step('security-report', 'Security Report', inputs.reportDrafts > 0 ? 'Ready' : inputs.evidenceRecords > 0 ? 'In progress' : 'Not started', inputs.reportDrafts, 'Review report before submission', 'reports'),
    step('submission', 'Submission', hasSubmitted(inputs.submissions) ? 'In progress' : inputs.submissions.length > 0 ? 'Ready' : inputs.reportDrafts > 0 ? 'Ready' : 'Not started', inputs.submissions.length, 'Track outcome', 'submission-tracker'),
    step('retest', 'Retest', inputs.retests.some((item) => item.status === 'retest_required') ? 'Needs review' : inputs.retests.length > 0 ? 'Completed' : acceptedOrResolved ? 'Ready' : 'Not started', inputs.retests.length, 'Complete retest notes', 'submission-tracker'),
  ]
}

function step(id: string, label: string, status: WorkflowStep['status'], count: number | string, nextAction: string, sectionId: string): WorkflowStep {
  return { id, label, status, count, readiness: status, nextAction, sectionId }
}

export function buildNextBestActions(steps: WorkflowStep[]): NextBestAction[] {
  const priority = steps.find((item) => item.status === 'Not started' || item.status === 'Ready' || item.status === 'Needs review')
  if (!priority) return [{ label: 'Review workflow records and keep retest outcomes current.', sectionId: 'submission-tracker', reason: 'All workflow stages have activity.' }]
  const labels: Record<string, string> = {
    'program-scope': 'Create or select a program scope.',
    recon: 'Run scope-aware recon on authorised assets.',
    endpoints: 'Analyse endpoints and parameters.',
    owasp: 'Review OWASP indicator mapping.',
    'safe-validation': 'Run safe validation on selected candidates.',
    evidence: 'Create evidence records from validation indicators.',
    'security-report': 'Generate or review a Security Finding Report.',
    submission: 'Track submission status.',
    retest: 'Record retest outcome.',
  }
  return [{ label: labels[priority.id] || priority.nextAction || 'Review next workflow step.', sectionId: priority.sectionId, reason: `${priority.label} is ${priority.status.toLowerCase()}.` }]
}

export function buildWorkflowTimeline(inputs: WorkflowInputs): WorkflowTimelineEvent[] {
  const events: WorkflowTimelineEvent[] = []
  if (inputs.scopesCount > 0) events.push(event('Program Scope available', 'Program Scope', 'scope'))
  if (inputs.reconReportsCount > 0) events.push(event('Recon results available', 'Recon Intelligence', 'recon'))
  if (inputs.endpointReportsCount > 0) events.push(event('Endpoint Intelligence report available', 'Endpoint Intelligence', 'endpoints'))
  if (inputs.owaspIndicators > 0) events.push(event('OWASP indicators mapped', 'OWASP Indicator Mapping', 'owasp'))
  if (inputs.safeValidationResults > 0) events.push(event('Safe Validation run available', 'Safe Validation', 'validation'))
  if (inputs.evidenceRecords > 0) events.push(event('Evidence records available', 'Evidence Capture', 'evidence'))
  if (inputs.reportDrafts > 0) events.push(event('Security Finding Report available', 'Security Finding Reports', 'reports'))
  inputs.submissions.forEach((item) => events.push(event(item.finding_title || item.report_id || 'Submission record', `Submission ${item.status || ''}`.trim(), 'submission', item.updated_at || item.created_at)))
  inputs.retests.forEach((item) => events.push(event(item.retest_id || 'Retest record', `Retest ${item.status || ''}`.trim(), 'retest', item.updated_at || item.created_at)))
  return events.sort((a, b) => String(b.event_time || '').localeCompare(String(a.event_time || ''))).slice(0, 20)
}

function event(title: string, eventType: string, source: string, time?: string): WorkflowTimelineEvent {
  return { title, event_type: eventType, source, event_time: time || 'Not timestamped' }
}
