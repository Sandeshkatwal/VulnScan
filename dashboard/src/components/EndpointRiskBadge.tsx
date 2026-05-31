interface EndpointRiskBadgeProps {
  label?: string
}

export function EndpointRiskBadge({ label = 'Informational' }: EndpointRiskBadgeProps) {
  const tone = label.toLowerCase().includes('high')
    ? 'status-badge--error'
    : label.toLowerCase().includes('medium')
      ? 'status-badge--warning'
      : 'status-badge--info'
  return <span className={`status-badge ${tone}`}>{label}</span>
}
