import type {
  FindingFilters,
  FindingsResponse,
  HealthResponse,
  JobDetail,
  JobResultResponse,
  JobsQuery,
  JobsResponse,
  ReportMetadataResponse,
  ReportsQuery,
  ReportsResponse,
  RemediationQuery,
  RemediationRecordResponse,
  RemediationResponse,
  RemediationSummary,
  RemediationUpdatePayload,
  RemediationUpdateResponse,
  BugBountyReconReportsResponse,
  BugBountyReconRequest,
  BugBountyReconResponse,
  AuthBoundaryResult,
  AuthEndpointClassificationResponse,
  AuthenticatedCrawlResponse,
  AuthProfilesResponse,
  BugIntelligenceMetricsResponse,
  DateRangeOption,
  DemoDatasetResponse,
  DemoStatusResponse,
  DiagnosticsResponse,
  BugBountyScopeDetail,
  BugBountyScopesResponse,
  DuplicateCheckRequest,
  DuplicateCheckResponse,
  DuplicateGroupsResponse,
  DuplicateSummary,
  EvidenceCreateRequest,
  EvidenceVaultResponse,
  FindingFingerprint,
  EndpointDiscoveryRequest,
  EndpointDiscoveryResponse,
  EndpointReportsResponse,
  OWASPCategoriesResponse,
  OWASPAssessmentBuildRequest,
  OWASPAssessmentResponse,
  OWASPAssessmentRulesResponse,
  OWASPReportBuildResponse,
  ProfessionalFindingRequest,
  ProfessionalFindingsResponse,
  ReportComposeRequest,
  ReportComposerResponse,
  A01AssessmentRequest,
  A01AssessmentResponse,
  A01ManualPlanRequest,
  A01ManualPlanResponse,
  A03AssessmentRequest,
  A03AssessmentResponse,
  A08AssessmentRequest,
  A08AssessmentResponse,
  A08ManualPlanRequest,
  A08ManualPlanResponse,
  A04AssessmentRequest,
  A04AssessmentResponse,
  A07AssessmentRequest,
  A07AssessmentResponse,
  A05AssessmentRequest,
  A05AssessmentResponse,
  A10AssessmentRequest,
  A10AssessmentResponse,
  AccessTestCreateRequest,
  AccessTestObserveRequest,
  AccessTestPlannerResponse,
  ParameterReplayPlannerResponse,
  ReplayPlanCreateRequest,
  ReplayPlanObserveRequest,
  BusinessLogicCreateRequest,
  BusinessLogicReviewResponse,
  OWASPMapRequest,
  OWASPMapResponse,
  RetestRecord,
  RetestsResponse,
  RoleEndpointMapRequest,
  RoleManualPlanRequest,
  RoleMappingResponse,
  SafeValidationRequest,
  SafeValidationResponse,
  ScanRequest,
  ScanResponse,
  ScansQuery,
  ScansResponse,
  SBOMAnalyseRequest,
  SBOMAnalyseResponse,
  ScopeCheckRequest,
  ScopeCheckResponse,
  SubmissionRecord,
  SubmissionSummary,
  SubmissionTimelineResponse,
  SubmissionsResponse,
  VersionResponse,
} from '../types/api'

const DEFAULT_API_BASE_URL = 'http://127.0.0.1:8088'

export const apiBaseUrl = (
  import.meta.env.VITE_VULSCAN_API_URL || DEFAULT_API_BASE_URL
).replace(/\/+$/, '')

const apiKey = import.meta.env.VITE_VULSCAN_API_KEY
export const apiKeyConfigured = Boolean(apiKey)

type QueryValue = boolean | number | string | null | undefined

export interface MetricsQuery {
  range?: DateRangeOption | string
  start_date?: string
  end_date?: string
  program_name?: string
}

function buildUrl(path: string, params?: Record<string, QueryValue>): string {
  const url = new URL(`${apiBaseUrl}${path}`)
  Object.entries(params || {}).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      url.searchParams.set(key, String(value))
    }
  })
  return url.toString()
}

export function buildApiUrl(path: string): string {
  if (/^https?:\/\//i.test(path)) return path
  return `${apiBaseUrl}${path.startsWith('/') ? path : `/${path}`}`
}

async function request<T>(
  path: string,
  options: RequestInit = {},
  params?: Record<string, QueryValue>,
): Promise<T> {
  const headers = new Headers(options.headers)
  headers.set('Accept', 'application/json')

  if (apiKey) {
    headers.set('X-VulScan-API-Key', apiKey)
  }

  const response = await fetch(buildUrl(path, params), {
    ...options,
    headers,
  })

  if (!response.ok) {
    let detail = `Request failed with status ${response.status}`
    try {
      const body = (await response.json()) as { detail?: string; error?: string }
      detail = body.detail || body.error || detail
    } catch {
      // Keep the generic HTTP status message.
    }
    throw new Error(detail)
  }

  return (await response.json()) as T
}

export function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/health')
}

export function getVersion(): Promise<VersionResponse> {
  return request<VersionResponse>('/version')
}

export function getDiagnostics(): Promise<DiagnosticsResponse> {
  return request<DiagnosticsResponse>('/diagnostics')
}

export function getJobs(params: JobsQuery | number = { limit: 10 }): Promise<JobsResponse> {
  const query = typeof params === 'number' ? { limit: params } : params
  return request<JobsResponse>('/jobs', {}, { ...query })
}

export function getCompletedJobs(limit = 50): Promise<JobsResponse> {
  return getJobs({ status: 'completed', limit })
}

export function getScans(params: ScansQuery | number = { limit: 10 }): Promise<ScansResponse> {
  const query = typeof params === 'number' ? { limit: params } : params
  return request<ScansResponse>('/scans', {}, { ...query })
}

export function getJob(jobId: string): Promise<JobDetail> {
  return request<JobDetail>(`/jobs/${encodeURIComponent(jobId)}`)
}

export function getJobResult(jobId: string): Promise<JobResultResponse> {
  return request<JobResultResponse>(`/jobs/${encodeURIComponent(jobId)}/result`)
}

export function getJobFindings(
  jobId: string,
  params: FindingFilters = {},
): Promise<FindingsResponse> {
  return request<FindingsResponse>(`/jobs/${encodeURIComponent(jobId)}/findings`, {}, { ...params })
}

export function getReports(params: ReportsQuery = { limit: 20 }): Promise<ReportsResponse> {
  return request<ReportsResponse>('/reports', {}, { ...params })
}

export function getRemediation(params: RemediationQuery = { limit: 20 }): Promise<RemediationResponse> {
  return request<RemediationResponse>('/remediation', {}, { ...params })
}

export function getRemediationSummary(): Promise<RemediationSummary> {
  return request<RemediationSummary>('/remediation/summary')
}

export function getRemediationRecord(findingKey: string): Promise<RemediationRecordResponse> {
  return request<RemediationRecordResponse>(`/remediation/${encodeURIComponent(findingKey)}`)
}

export function updateRemediation(
  findingKey: string,
  payload: RemediationUpdatePayload,
): Promise<RemediationUpdateResponse> {
  return request<RemediationUpdateResponse>(`/remediation/${encodeURIComponent(findingKey)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function getReportMetadata(reportId: string): Promise<ReportMetadataResponse> {
  return request<ReportMetadataResponse>(`/reports/${encodeURIComponent(reportId)}/metadata`)
}

export function getReportViewUrl(reportId: string): string {
  return buildApiUrl(`/reports/${encodeURIComponent(reportId)}/view`)
}

export function downloadReport(reportId: string, filename?: string): Promise<void> {
  return authenticatedDownload(`/reports/${encodeURIComponent(reportId)}/download`, filename)
}

export async function authenticatedDownload(
  path: string,
  filename = 'vulscan-report',
  openInNewTab = false,
): Promise<void> {
  const headers = new Headers()
  if (apiKey) {
    headers.set('X-VulScan-API-Key', apiKey)
  }

  const response = await fetch(buildApiUrl(path), { headers })
  if (!response.ok) {
    let detail = `Report request failed with status ${response.status}`
    try {
      const body = (await response.json()) as { detail?: string; error?: string }
      detail = body.detail || body.error || detail
    } catch {
      // Keep the generic HTTP status message.
    }
    throw new Error(detail)
  }

  const blob = await response.blob()
  const objectUrl = URL.createObjectURL(blob)

  if (openInNewTab) {
    window.open(objectUrl, '_blank', 'noopener,noreferrer')
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000)
    return
  }

  const anchor = document.createElement('a')
  anchor.href = objectUrl
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 10_000)
}

export function createScan(requestBody: ScanRequest): Promise<ScanResponse> {
  return request<ScanResponse>('/scans', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scan_mode: 'safe', ...requestBody }),
  })
}

export function getBugBountyScopes(): Promise<BugBountyScopesResponse> {
  return request<BugBountyScopesResponse>('/program-scope/scopes')
}

export function getBugBountyScope(programId: string): Promise<BugBountyScopeDetail> {
  return request<BugBountyScopeDetail>(`/program-scope/scopes/${encodeURIComponent(programId)}`)
}

export function checkBugBountyScope(payload: ScopeCheckRequest): Promise<ScopeCheckResponse> {
  return request<ScopeCheckResponse>('/program-scope/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function runBugBountyRecon(payload: BugBountyReconRequest): Promise<BugBountyReconResponse> {
  return request<BugBountyReconResponse>('/recon', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function getBugBountyReconResults(): Promise<BugBountyReconReportsResponse> {
  return request<BugBountyReconReportsResponse>('/recon/results')
}

export function analyseEndpoints(payload: EndpointDiscoveryRequest): Promise<EndpointDiscoveryResponse> {
  return request<EndpointDiscoveryResponse>('/endpoints/analyse', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function getEndpointReports(): Promise<EndpointReportsResponse> {
  return request<EndpointReportsResponse>('/endpoints/reports')
}

export function getAuthProfiles(): Promise<AuthProfilesResponse> {
  return request<AuthProfilesResponse>('/auth/profiles')
}

export function checkAuthBoundary(profile: Record<string, unknown>, url: string): Promise<AuthBoundaryResult> {
  return request<AuthBoundaryResult>('/auth/boundary/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ profile, url }),
  })
}

export function classifyAuthEndpoints(profile: Record<string, unknown>, endpointResults: Array<Record<string, unknown>>): Promise<AuthEndpointClassificationResponse> {
  return request<AuthEndpointClassificationResponse>('/auth/endpoints/classify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ profile, endpoint_results: endpointResults }),
  })
}

export function runAuthenticatedCrawl(payload: {
  url: string
  profile: Record<string, unknown>
  max_pages: number
  max_depth: number
  request_delay: number
  timeout: number
  same_origin_only: boolean
  dry_run: boolean
}): Promise<AuthenticatedCrawlResponse> {
  return request<AuthenticatedCrawlResponse>('/authenticated/crawl', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function getRoles(): Promise<RoleMappingResponse> {
  return request<RoleMappingResponse>('/roles')
}

export function mapRoleEndpoints(payload: RoleEndpointMapRequest): Promise<RoleMappingResponse> {
  return request<RoleMappingResponse>('/roles/map-endpoints', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function buildRoleManualPlan(payload: RoleManualPlanRequest): Promise<RoleMappingResponse> {
  return request<RoleMappingResponse>('/roles/manual-plan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function createAccessTest(payload: AccessTestCreateRequest): Promise<AccessTestPlannerResponse> {
  return request<AccessTestPlannerResponse>('/access-tests/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function observeAccessTest(payload: AccessTestObserveRequest): Promise<AccessTestPlannerResponse> {
  return request<AccessTestPlannerResponse>('/access-tests/observe', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function retestAccessTest(payload: {
  test_plan_id: string
  retest_status: string
  remediation_summary?: string
  retest_observed_result?: string
  retest_notes?: string
}): Promise<AccessTestPlannerResponse> {
  return request<AccessTestPlannerResponse>('/access-tests/retest', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function buildAccessTestReportTemplate(payload: {
  plan: Record<string, unknown>
  observation?: Record<string, unknown> | null
  retest?: Record<string, unknown> | null
}): Promise<AccessTestPlannerResponse> {
  return request<AccessTestPlannerResponse>('/access-tests/report-template', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function createReplayPlan(payload: ReplayPlanCreateRequest): Promise<ParameterReplayPlannerResponse> {
  return request<ParameterReplayPlannerResponse>('/replay-plans/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function observeReplayPlan(payload: ReplayPlanObserveRequest): Promise<ParameterReplayPlannerResponse> {
  return request<ParameterReplayPlannerResponse>('/replay-plans/observe', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function retestReplayPlan(payload: {
  replay_plan_id: string
  retest_status: string
  remediation_summary?: string
  retest_observed_result?: string
  retest_notes?: string
}): Promise<ParameterReplayPlannerResponse> {
  return request<ParameterReplayPlannerResponse>('/replay-plans/retest', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function buildReplayPlanReportTemplate(payload: {
  plan: Record<string, unknown>
  observation?: Record<string, unknown> | null
  retest?: Record<string, unknown> | null
}): Promise<ParameterReplayPlannerResponse> {
  return request<ParameterReplayPlannerResponse>('/replay-plans/report-template', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function detectBusinessLogic(payload: {
  endpoint_results: Array<Record<string, unknown>>
  parameter_results?: Array<Record<string, unknown>>
  role_matrix?: Array<Record<string, unknown>> | Record<string, unknown> | null
  replay_plans?: Array<Record<string, unknown>>
}): Promise<BusinessLogicReviewResponse> {
  return request<BusinessLogicReviewResponse>('/business-logic/detect', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function createBusinessLogicPlan(payload: BusinessLogicCreateRequest): Promise<BusinessLogicReviewResponse> {
  return request<BusinessLogicReviewResponse>('/business-logic/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function observeBusinessLogic(payload: {
  review_plan_id: string
  observed_result: string
  observed_status_code?: number | null
  observed_message_summary?: string
  evidence_summary?: string
  tester_notes?: string
}): Promise<BusinessLogicReviewResponse> {
  return request<BusinessLogicReviewResponse>('/business-logic/observe', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function retestBusinessLogic(payload: {
  review_plan_id: string
  retest_status: string
  remediation_summary?: string
  retest_observed_result?: string
  retest_notes?: string
}): Promise<BusinessLogicReviewResponse> {
  return request<BusinessLogicReviewResponse>('/business-logic/retest', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function buildBusinessLogicReportTemplate(payload: {
  plan: Record<string, unknown>
  observation?: Record<string, unknown> | null
  retest?: Record<string, unknown> | null
}): Promise<BusinessLogicReviewResponse> {
  return request<BusinessLogicReviewResponse>('/business-logic/report-template', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function getOWASPCategories(): Promise<OWASPCategoriesResponse> {
  return request<OWASPCategoriesResponse>('/owasp/categories')
}

export function mapOWASP(payload: OWASPMapRequest): Promise<OWASPMapResponse> {
  return request<OWASPMapResponse>('/owasp/map', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function getOWASPAssessmentRules(): Promise<OWASPAssessmentRulesResponse> {
  return request<OWASPAssessmentRulesResponse>('/owasp/assessment/rules')
}

export function buildOWASPAssessment(payload: OWASPAssessmentBuildRequest): Promise<OWASPAssessmentResponse> {
  return request<OWASPAssessmentResponse>('/owasp/assessment/build', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function buildOWASPReport(payload: OWASPAssessmentBuildRequest): Promise<OWASPReportBuildResponse> {
  return request<OWASPReportBuildResponse>('/owasp/report/build', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function downloadOWASPReport(reportId: string, filename?: string): Promise<void> {
  return authenticatedDownload(`/owasp/report/${encodeURIComponent(reportId)}/download`, filename || `${reportId}.md`)
}

export function assessA01AccessControl(payload: A01AssessmentRequest): Promise<A01AssessmentResponse> {
  return request<A01AssessmentResponse>('/owasp/a01/assess', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function buildA01ManualPlan(payload: A01ManualPlanRequest): Promise<A01ManualPlanResponse> {
  return request<A01ManualPlanResponse>('/owasp/a01/manual-plan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function assessA03SupplyChain(payload: A03AssessmentRequest): Promise<A03AssessmentResponse> {
  return request<A03AssessmentResponse>('/owasp/a03/assess', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function assessA08Integrity(payload: A08AssessmentRequest): Promise<A08AssessmentResponse> {
  return request<A08AssessmentResponse>('/owasp/a08/assess', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function buildA08ManualPlan(payload: A08ManualPlanRequest): Promise<A08ManualPlanResponse> {
  return request<A08ManualPlanResponse>('/owasp/a08/manual-plan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function analyseSBOM(payload: SBOMAnalyseRequest): Promise<SBOMAnalyseResponse> {
  return request<SBOMAnalyseResponse>('/sbom/analyse', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function assessA04Crypto(payload: A04AssessmentRequest): Promise<A04AssessmentResponse> {
  return request<A04AssessmentResponse>('/owasp/a04/assess', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function assessA07Authentication(payload: A07AssessmentRequest): Promise<A07AssessmentResponse> {
  return request<A07AssessmentResponse>('/owasp/a07/assess', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function assessA05Injection(payload: A05AssessmentRequest): Promise<A05AssessmentResponse> {
  return request<A05AssessmentResponse>('/owasp/a05/assess', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function assessA10ErrorHandling(payload: A10AssessmentRequest): Promise<A10AssessmentResponse> {
  return request<A10AssessmentResponse>('/owasp/a10/assess', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function runSafeValidation(payload: SafeValidationRequest): Promise<SafeValidationResponse> {
  return request<SafeValidationResponse>('/safe-validation', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function getSubmissions(params: { status?: string } = {}): Promise<SubmissionsResponse> {
  const search = new URLSearchParams()
  if (params.status) search.set('status', params.status)
  const suffix = search.toString() ? `?${search.toString()}` : ''
  return request<SubmissionsResponse>(`/submissions${suffix}`)
}

export function getSubmission(submissionId: string): Promise<SubmissionRecord> {
  return request<SubmissionRecord>(`/submissions/${encodeURIComponent(submissionId)}`)
}

export function createSubmission(payload: Partial<SubmissionRecord>): Promise<SubmissionRecord> {
  return request<SubmissionRecord>('/submissions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function updateSubmission(submissionId: string, payload: Partial<SubmissionRecord>): Promise<SubmissionRecord> {
  return request<SubmissionRecord>(`/submissions/${encodeURIComponent(submissionId)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function updateSubmissionStatus(submissionId: string, payload: { status: string; note?: string }): Promise<SubmissionRecord> {
  return request<SubmissionRecord>(`/submissions/${encodeURIComponent(submissionId)}/status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function addSubmissionNote(submissionId: string, note: string): Promise<SubmissionRecord> {
  return request<SubmissionRecord>(`/submissions/${encodeURIComponent(submissionId)}/notes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ note }),
  })
}

export function getSubmissionTimeline(submissionId: string): Promise<SubmissionTimelineResponse> {
  return request<SubmissionTimelineResponse>(`/submissions/${encodeURIComponent(submissionId)}/timeline`)
}

export function getSubmissionSummary(): Promise<SubmissionSummary> {
  return request<SubmissionSummary>('/submissions/summary')
}

export function fingerprintDuplicate(payload: DuplicateCheckRequest): Promise<{ fingerprint: FindingFingerprint }> {
  return request<{ fingerprint: FindingFingerprint }>('/duplicates/fingerprint', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function checkDuplicate(payload: DuplicateCheckRequest): Promise<DuplicateCheckResponse> {
  return request<DuplicateCheckResponse>('/duplicates/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function getDuplicateGroups(): Promise<DuplicateGroupsResponse> {
  return request<DuplicateGroupsResponse>('/duplicates/groups')
}

export function getDuplicateGroup(groupId: string): Promise<DuplicateGroupsResponse['groups'][number]> {
  return request<DuplicateGroupsResponse['groups'][number]>(`/duplicates/groups/${encodeURIComponent(groupId)}`)
}

export function getFingerprint(fingerprintId: string): Promise<FindingFingerprint> {
  return request<FindingFingerprint>(`/duplicates/fingerprints/${encodeURIComponent(fingerprintId)}`)
}

export function getDuplicateSummary(): Promise<DuplicateSummary> {
  return request<DuplicateSummary>('/duplicates/summary')
}

export function getRetests(params: { submission_id?: string } = {}): Promise<RetestsResponse> {
  const search = new URLSearchParams()
  if (params.submission_id) search.set('submission_id', params.submission_id)
  const suffix = search.toString() ? `?${search.toString()}` : ''
  return request<RetestsResponse>(`/retests${suffix}`)
}

export function getBugIntelligenceMetrics(params: MetricsQuery = {}): Promise<BugIntelligenceMetricsResponse> {
  return request<BugIntelligenceMetricsResponse>('/bug-intelligence/metrics/summary', {}, { ...params })
}

export function createRetest(payload: Partial<RetestRecord>): Promise<RetestRecord> {
  return request<RetestRecord>('/retests', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function updateRetest(retestId: string, payload: Partial<RetestRecord>): Promise<RetestRecord> {
  return request<RetestRecord>(`/retests/${encodeURIComponent(retestId)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function getEvidenceVault(): Promise<EvidenceVaultResponse> {
  return request<EvidenceVaultResponse>('/evidence')
}

export function createEvidenceItem(payload: EvidenceCreateRequest): Promise<EvidenceVaultResponse> {
  return request<EvidenceVaultResponse>('/evidence', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function redactEvidenceText(text: string): Promise<EvidenceVaultResponse> {
  return request<EvidenceVaultResponse>('/evidence/redact-check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
  })
}

export function getEvidenceQuality(evidenceId: string): Promise<EvidenceVaultResponse> {
  return request<EvidenceVaultResponse>(`/evidence/${encodeURIComponent(evidenceId)}/quality`, { method: 'POST' })
}

export function getEvidenceTimeline(evidenceId: string): Promise<EvidenceVaultResponse> {
  return request<EvidenceVaultResponse>(`/evidence/${encodeURIComponent(evidenceId)}/timeline`)
}

export function linkEvidence(evidenceId: string, payload: { link_type: string; linked_id: string }): Promise<EvidenceVaultResponse> {
  return request<EvidenceVaultResponse>(`/evidence/${encodeURIComponent(evidenceId)}/link`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function exportEvidence(payload: { evidence_ids: string[]; markdown?: boolean; json?: boolean }): Promise<EvidenceVaultResponse> {
  return request<EvidenceVaultResponse>('/evidence/export', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function getProfessionalFindings(): Promise<ProfessionalFindingsResponse> {
  return request<ProfessionalFindingsResponse>('/reports/findings')
}

export function getProfessionalFinding(findingId: string): Promise<ProfessionalFindingsResponse> {
  return request<ProfessionalFindingsResponse>(`/reports/findings/${encodeURIComponent(findingId)}`)
}

export function createProfessionalFinding(payload: ProfessionalFindingRequest): Promise<ProfessionalFindingsResponse> {
  return request<ProfessionalFindingsResponse>('/reports/finding', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function createFindingFromEvidence(evidenceId: string): Promise<ProfessionalFindingsResponse> {
  return request<ProfessionalFindingsResponse>('/reports/finding/from-evidence', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ evidence_id: evidenceId }),
  })
}

export function composeProfessionalReport(payload: ReportComposeRequest): Promise<ReportComposerResponse> {
  return request<ReportComposerResponse>('/reports/compose', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function checkProfessionalReportSafety(payload: Partial<ReportComposeRequest>): Promise<ReportComposerResponse> {
  return request<ReportComposerResponse>('/reports/export-safety-check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function getDemoStatus(): Promise<DemoStatusResponse> {
  return request<DemoStatusResponse>('/demo/status')
}

export function getDemoDashboard(): Promise<DemoDatasetResponse> {
  return request<DemoDatasetResponse>('/demo/dashboard')
}

export function generateDemoDataset(): Promise<DemoDatasetResponse> {
  return request<DemoDatasetResponse>('/demo/generate', { method: 'POST' })
}

export function buildDemoReport(payload: { markdown?: boolean; html?: boolean; json?: boolean } = { markdown: true, html: true, json: true }): Promise<ReportComposerResponse> {
  return request<ReportComposerResponse>('/demo/report/build', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}
