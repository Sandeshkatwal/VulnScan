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
  BugIntelligenceMetricsResponse,
  DateRangeOption,
  BugBountyScopeDetail,
  BugBountyScopesResponse,
  DuplicateCheckRequest,
  DuplicateCheckResponse,
  DuplicateGroupsResponse,
  DuplicateSummary,
  FindingFingerprint,
  EndpointDiscoveryRequest,
  EndpointDiscoveryResponse,
  EndpointReportsResponse,
  OWASPCategoriesResponse,
  OWASPMapRequest,
  OWASPMapResponse,
  RetestRecord,
  RetestsResponse,
  SafeValidationRequest,
  SafeValidationResponse,
  ScanRequest,
  ScanResponse,
  ScansQuery,
  ScansResponse,
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
