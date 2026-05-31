interface OWASPBadgeProps {
  confidence?: string
}

export function OWASPBadge({ confidence = 'Low' }: OWASPBadgeProps) {
  const tone = confidence === 'High' ? 'status-badge--error' : confidence === 'Medium' ? 'status-badge--warning' : 'status-badge--info'
  return <span className={`status-badge ${tone}`}>{confidence}</span>
}
