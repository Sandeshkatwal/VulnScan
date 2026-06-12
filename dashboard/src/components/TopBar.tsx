import { RefreshCw, ShieldCheck } from 'lucide-react'
import type { HealthResponse, VersionResponse } from '../types/api'
import { ApiStatus } from './ApiStatus'

interface TopBarProps {
  apiBaseUrl: string
  apiError?: string | null
  health?: HealthResponse | null
  loading?: boolean
  selectedIndicator?: string
  title: string
  version?: VersionResponse | null
  onRefresh: () => void
}

export function TopBar({
  apiBaseUrl,
  apiError,
  health,
  loading = false,
  selectedIndicator,
  title,
  version,
  onRefresh,
}: TopBarProps) {
  return (
    <header className="dashboard-topbar">
      <div className="topbar-title">
        <ShieldCheck aria-hidden="true" size={26} />
        <div>
          <h1>{title}</h1>
          <p>{selectedIndicator || 'No job selected'}</p>
        </div>
      </div>
      <div className="header-actions">
        <span className="demo-dataset-badge">Local Demo Only</span>
        <ApiStatus health={health} version={version} error={apiError} loading={loading} />
        <div className="api-base" title={apiBaseUrl}>
          <span>API</span>
          <code>{apiBaseUrl}</code>
        </div>
        <button className="icon-button" type="button" onClick={onRefresh} disabled={loading} title="Refresh dashboard data">
          <RefreshCw aria-hidden="true" size={18} />
          <span className="sr-only">Refresh dashboard data</span>
        </button>
      </div>
    </header>
  )
}

export const Topbar = TopBar
