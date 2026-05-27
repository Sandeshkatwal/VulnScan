import type { ReactNode } from 'react'
import { RefreshCw, ShieldCheck } from 'lucide-react'
import { ApiStatus } from './ApiStatus'
import type { HealthResponse, VersionResponse } from '../types/api'

interface LayoutProps {
  apiBaseUrl: string
  health?: HealthResponse | null
  version?: VersionResponse | null
  apiError?: string | null
  loading?: boolean
  onRefresh: () => void
  children: ReactNode
}

export function Layout({
  apiBaseUrl,
  health,
  version,
  apiError,
  loading = false,
  onRefresh,
  children,
}: LayoutProps) {
  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand">
          <ShieldCheck aria-hidden="true" size={28} />
          <div>
            <h1>VulScan Dashboard</h1>
            <p>Local development console for authorised scan history and prioritisation.</p>
          </div>
        </div>
        <div className="header-actions">
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
      <main>{children}</main>
    </div>
  )
}
