interface ValidationStatusBadgeProps {
  status?: string
  indicator?: boolean
}

export function ValidationStatusBadge({ status = 'checked', indicator = false }: ValidationStatusBadgeProps) {
  const tone = indicator ? 'status-badge--warning' : status === 'error' ? 'status-badge--error' : 'status-badge--info'
  return <span className={`status-badge ${tone}`}>{indicator ? 'Indicator' : status}</span>
}
