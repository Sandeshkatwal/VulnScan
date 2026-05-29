import type { ReactNode } from 'react'
import type { HealthResponse, VersionResponse } from '../types/api'
import { DashboardShell } from './DashboardShell'
import type { NavigationItem } from './Sidebar'

interface LayoutProps {
  activeSection?: string
  apiBaseUrl: string
  health?: HealthResponse | null
  version?: VersionResponse | null
  apiError?: string | null
  loading?: boolean
  navigationItems?: NavigationItem[]
  selectedIndicator?: string
  title?: string
  onRefresh: () => void
  onSelectSection?: (section: string) => void
  children: ReactNode
}

export function Layout({
  activeSection = 'overview',
  apiBaseUrl,
  health,
  version,
  apiError,
  loading = false,
  navigationItems = [],
  selectedIndicator,
  title = 'VulScan Dashboard',
  onRefresh,
  onSelectSection = () => undefined,
  children,
}: LayoutProps) {
  if (navigationItems.length) {
    return (
      <DashboardShell
        activeSection={activeSection}
        apiBaseUrl={apiBaseUrl}
        apiError={apiError}
        health={health}
        loading={loading}
        navigationItems={navigationItems}
        selectedIndicator={selectedIndicator}
        title={title}
        version={version}
        onRefresh={onRefresh}
        onSelectSection={onSelectSection}
      >
        {children}
      </DashboardShell>
    )
  }

  return (
    <div className="app-shell">
      <main>{children}</main>
    </div>
  )
}
