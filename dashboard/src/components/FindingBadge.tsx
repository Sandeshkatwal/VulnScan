interface FindingBadgeProps {
  type: 'severity' | 'priority' | 'status' | 'exploit'
  value?: string | boolean | null
}

function tone(type: FindingBadgeProps['type'], value?: string | boolean | null): string {
  const text = String(value ?? '').toLowerCase()
  if (type === 'severity') {
    if (text === 'critical' || text === 'high') return 'bad'
    if (text === 'medium') return 'warn'
    if (text === 'low') return 'neutral'
    return 'good'
  }
  if (type === 'priority') {
    if (text === 'fix first') return 'bad'
    if (text === 'fix soon' || text === 'schedule') return 'warn'
    if (text === 'monitor') return 'neutral'
    return 'good'
  }
  if (type === 'status') {
    if (text === 'completed') return 'good'
    if (text === 'failed' || text === 'cancelled') return 'bad'
    if (text === 'queued' || text === 'running') return 'warn'
    return 'neutral'
  }
  if (value === true || text === 'active exploitation reported') return 'bad'
  if (text === 'false' || value === false) return 'neutral'
  return 'warn'
}

function label(type: FindingBadgeProps['type'], value?: string | boolean | null): string {
  if (type === 'exploit') {
    if (value === true) return 'Exploit metadata available'
    if (value === false) return 'No exploit metadata'
  }
  return value === null || value === undefined || value === '' ? 'Not available' : String(value)
}

export function FindingBadge({ type, value }: FindingBadgeProps) {
  return <span className={`badge badge--${tone(type, value)}`}>{label(type, value)}</span>
}
