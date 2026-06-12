import type { HealthResponse, VersionResponse } from '../types/api'

interface ApiConnectionStatusProps {
  apiBaseUrl: string
  error?: string | null
  health?: HealthResponse | null
  loading?: boolean
  version?: VersionResponse | null
}

export function ApiConnectionStatus({ apiBaseUrl, error, health, loading = false, version }: ApiConnectionStatusProps) {
  const reachable = health?.status === 'ok' || health?.status === 'warning'
  return (
    <article className="panel">
      <div className="panel-heading">
        <h2>API Connection Status</h2>
        <p>Local API availability and beta metadata.</p>
      </div>
      <div className="beta-status-grid">
        <div><span>Status</span><strong>{loading ? 'Checking' : reachable && !error ? 'Reachable' : 'Unavailable'}</strong></div>
        <div><span>API URL</span><strong>{apiBaseUrl}</strong></div>
        <div><span>Version</span><strong>{version?.version || health?.version || 'Unavailable'}</strong></div>
        <div><span>Safety</span><strong>{version?.authorised_use_only ?? health?.authorised_use_only ? 'Authorised testing only' : 'Check configuration'}</strong></div>
      </div>
      {error ? <div className="empty-state">Start the local API or enable demo mode to continue reviewing dashboard workflows.</div> : null}
    </article>
  )
}
