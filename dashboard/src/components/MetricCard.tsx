interface Props {
  label: string
  value: string | number
  detail?: string
}

export function MetricCard({ label, value, detail }: Props) {
  return (
    <div className="metric-card">
      <span>{label}</span>
      <strong>{value}</strong>
      {detail ? <p>{detail}</p> : null}
    </div>
  )
}

