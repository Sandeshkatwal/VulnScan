import { formatValue } from '../utils/format'

interface ReportPathBadgeProps {
  label: string
  path?: string | null
}

export function ReportPathBadge({ label, path }: ReportPathBadgeProps) {
  const available = Boolean(path)
  return (
    <span className={`report-path-badge report-path-badge--${available ? 'available' : 'missing'}`} title={formatValue(path)}>
      {label}: {available ? 'Available' : 'Not available'}
    </span>
  )
}
