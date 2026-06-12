import type { HealthResponse } from '../types/api'

interface SystemHealthPanelProps {
  health?: HealthResponse | null
}

export function SystemHealthPanel({ health }: SystemHealthPanelProps) {
  const warnings = Array.isArray(health?.warnings) ? health.warnings : []
  return (
    <article className="panel">
      <div className="panel-heading">
        <h2>System Health</h2>
        <p>Safe local readiness checks.</p>
      </div>
      <div className="beta-status-grid">
        <div><span>Status</span><strong>{health?.status || 'Unavailable'}</strong></div>
        <div><span>Reports</span><strong>{health?.reports_writable ? 'Writable' : 'Not verified'}</strong></div>
        <div><span>Demo data</span><strong>{health?.demo_data_exists ? 'Present' : 'Missing'}</strong></div>
        <div><span>Samples</span><strong>{health?.safe_sample_files_exist ? 'Present' : 'Missing'}</strong></div>
      </div>
      {warnings.length ? (
        <ul className="beta-list">
          {warnings.map((warning) => <li key={warning}>{warning}</li>)}
        </ul>
      ) : <div className="empty-state">No health warnings reported.</div>}
    </article>
  )
}
