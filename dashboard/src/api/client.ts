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
  BugBountyScopeDetail,
  BugBountyScopesResponse,
  EndpointDiscoveryRequest,
  EndpointDiscoveryResponse,
  ScanRequest,
  ScanResponse,
  ScansQuery,
  ScansResponse,
  ScopeCheckRequest,
  ScopeCheckResponse,
  VersionResponse,
} from '../types/api'

const DEFAULT_API_BASE_URL = 'http://127.0.0.1:8088'

export const apiBaseUrl = (
  import.meta.env.VITE_VULSCAN_API_URL || DEFAULT_API_BASE_URL
).replace(/\/+$/, '')

const apiKey = import.meta.env.VITE_VULSCAN_API_KEY
export const apiKeyConfigured = Boolean(apiKey)

type QueryValue = boolean | number | string | null | undefined

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
  return request<BugBountyScopesResponse>('/bug-bounty/scopes')
}

export function getBugBountyScope(programId: string): Promise<BugBountyScopeDetail> {
  return request<BugBountyScopeDetail>(`/bug-bounty/scopes/${encodeURIComponent(programId)}`)
}

export function checkBugBountyScope(payload: ScopeCheckRequest): Promise<ScopeCheckResponse> {
  return request<ScopeCheckResponse>('/bug-bounty/scope-check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function runBugBountyRecon(payload: BugBountyReconRequest): Promise<BugBountyReconResponse> {
  return request<BugBountyReconResponse>('/bug-bounty/recon', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function getBugBountyReconResults(): Promise<BugBountyReconReportsResponse> {
  return request<BugBountyReconReportsResponse>('/bug-bounty/recon/results')
}

export function analyseEndpoints(payload: EndpointDiscoveryRequest): Promise<EndpointDiscoveryResponse> {
  return request<EndpointDiscoveryResponse>('/bug-bounty/endpoints/analyse', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}
