import { RetryPanel } from './RetryPanel'

interface DashboardFallbackStateProps {
  onRetry: () => void
}

export function DashboardFallbackState({ onRetry }: DashboardFallbackStateProps) {
  return (
    <article className="panel panel--wide">
      <div className="panel-heading">
        <h2>Dashboard Resilience</h2>
        <p>A dashboard section could not render safely.</p>
      </div>
      <RetryPanel message="Return to a safe local state and refresh dashboard data." onRetry={onRetry} retryLabel="Refresh" />
    </article>
  )
}
