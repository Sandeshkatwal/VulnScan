import type {
  FindingsResponse,
  HealthResponse,
  JobsResponse,
  ScanRequest,
  ScansResponse,
  VersionResponse,
} from '../types/api'

const DEFAULT_API_BASE_URL = 'http://127.0.0.1:8088'

export const apiBaseUrl = (
  import.meta.env.VITE_VULSCAN_API_URL || DEFAULT_API_BASE_URL
).replace(/\/+$/, '')

const apiKey = import.meta.env.VITE_VULSCAN_API_KEY

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

export function getJobs(limit = 10): Promise<JobsResponse> {
  return request<JobsResponse>('/jobs', {}, { limit })
}

export function getScans(limit = 10): Promise<ScansResponse> {
  return request<ScansResponse>('/scans', {}, { limit })
}

export function getJobFindings(
  jobId: string,
  params: Record<string, QueryValue> = {},
): Promise<FindingsResponse> {
  return request<FindingsResponse>(`/jobs/${encodeURIComponent(jobId)}/findings`, {}, params)
}

export function createScan(requestBody: ScanRequest) {
  return request('/scans', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scan_mode: 'safe', ...requestBody }),
  })
}
