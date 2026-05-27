import type { HealthResponse, VersionResponse } from '../types/api'

interface ApiStatusProps {
  health?: HealthResponse | null
  version?: VersionResponse | null
  error?: string | null
  loading?: boolean
}

export function ApiStatus({ health, version, error, loading = false }: ApiStatusProps) {
  const reachable = health?.status === 'ok' && !error
  const label = loading ? 'Checking' : reachable ? 'Reachable' : 'Unreachable'
  const versionText = version?.version
    ? `Scanner ${version.version}${version.api_version ? ` / API ${version.api_version}` : ''}`
    : 'Version unavailable'

  return (
    <div className="api-status" aria-label="Local API status">
      <span className={`status-dot ${reachable ? 'status-dot--good' : loading ? 'status-dot--warn' : 'status-dot--bad'}`} />
      <div>
        <strong>{label}</strong>
        <span>{error ? 'Check that the local API is running and the key is configured.' : versionText}</span>
      </div>
    </div>
  )
}
