interface DistributionChartProps {
  title: string
  data: Record<string, number>
}

export function DistributionChart({ title, data }: DistributionChartProps) {
  const entries = Object.entries(data)
  const max = Math.max(1, ...entries.map(([, count]) => count))

  return (
    <div className="distribution-card">
      <h3>{title}</h3>
      <div className="distribution-bars" aria-hidden="true">
        {entries.map(([label, count]) => (
          <div className="distribution-bar" key={label}>
            <span>{label}</span>
            <div>
              <i style={{ width: `${Math.max(3, (count / max) * 100)}%` }} />
            </div>
            <strong>{count}</strong>
          </div>
        ))}
      </div>
      <ul className="distribution-list" aria-label={`${title} counts`}>
        {entries.map(([label, count]) => (
          <li key={label}>
            <span>{label}</span>
            <strong>{count}</strong>
          </li>
        ))}
      </ul>
    </div>
  )
}
