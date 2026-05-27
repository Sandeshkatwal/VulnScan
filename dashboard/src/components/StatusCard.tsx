interface StatusCardProps {
  label: string
  value: string | number
  description?: string
  tone?: 'neutral' | 'good' | 'warn' | 'bad'
}

export function StatusCard({ label, value, description, tone = 'neutral' }: StatusCardProps) {
  return (
    <article className={`status-card status-card--${tone}`}>
      <span className="status-card__label">{label}</span>
      <strong className="status-card__value">{value}</strong>
      {description ? <span className="status-card__description">{description}</span> : null}
    </article>
  )
}
