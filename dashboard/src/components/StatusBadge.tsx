interface Props {
  label: string
  tone?: 'neutral' | 'good' | 'warning' | 'bad'
}

export function StatusBadge({ label, tone = 'neutral' }: Props) {
  return <span className={`status-badge status-badge--${tone}`}>{label}</span>
}

