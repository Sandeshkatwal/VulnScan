import type { ReactNode } from 'react'
import type { HealthResponse, VersionResponse } from '../types/api'
import { LocalOnlyNotice } from './LocalOnlyNotice'
import { Sidebar, type NavigationItem } from './Sidebar'
import { TopBar } from './TopBar'

interface DashboardShellProps {
  activeSection: string
  apiBaseUrl: string
  apiError?: string | null
  children: ReactNode
  health?: HealthResponse | null
  loading?: boolean
  navigationItems: NavigationItem[]
  selectedIndicator?: string
  title: string
  version?: VersionResponse | null
  onRefresh: () => void
  onSelectSection: (section: string) => void
}

export function DashboardShell({
  activeSection,
  apiBaseUrl,
  apiError,
  children,
  health,
  loading = false,
  navigationItems,
  selectedIndicator,
  title,
  version,
  onRefresh,
  onSelectSection,
}: DashboardShellProps) {
  return (
    <div className="dashboard-shell">
      <Sidebar items={navigationItems} activeItem={activeSection} onSelect={onSelectSection} />
      <div className="dashboard-main">
        <TopBar
          apiBaseUrl={apiBaseUrl}
          apiError={apiError}
          health={health}
          loading={loading}
          selectedIndicator={selectedIndicator}
          title={title}
          version={version}
          onRefresh={onRefresh}
        />
        <LocalOnlyNotice />
        <main className="dashboard-content">{children}</main>
      </div>
    </div>
  )
}
