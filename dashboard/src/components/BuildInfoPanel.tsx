import type { VersionResponse } from '../types/api'

interface BuildInfoPanelProps {
  version?: VersionResponse | null
}

export function BuildInfoPanel({ version }: BuildInfoPanelProps) {
  return (
    <article className="panel">
      <div className="panel-heading">
        <h2>Build Info</h2>
        <p>Version Metadata and beta channel.</p>
      </div>
      <div className="beta-status-grid">
        <div><span>Version</span><strong>{version?.version || '22.1.0-beta'}</strong></div>
        <div><span>Channel</span><strong>{version?.release_channel || 'public-beta'}</strong></div>
        <div><span>Status</span><strong>{version?.build_status || 'bug-fix-sprint'}</strong></div>
        <div><span>Use</span><strong>Authorised testing only</strong></div>
      </div>
    </article>
  )
}
