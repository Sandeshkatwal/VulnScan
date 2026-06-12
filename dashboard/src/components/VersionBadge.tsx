import type { VersionResponse } from '../types/api'

interface VersionBadgeProps {
  version?: VersionResponse | null
}

export function VersionBadge({ version }: VersionBadgeProps) {
  const label = version?.version || '22.0.0-beta'
  const channel = version?.release_channel || 'public-beta'
  return (
    <span className="version-badge" title="VulScan Version Metadata">
      VulScan {label} · {channel}
    </span>
  )
}
