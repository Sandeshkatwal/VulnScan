interface ScopeRulesTableProps {
  title: string
  rules?: Record<string, unknown>
}

const labels: Record<string, string> = {
  domains: 'Domains',
  urls: 'URLs',
  api_base_urls: 'API base URLs',
  ip_ranges: 'IP ranges',
}

export function ScopeRulesTable({ title, rules = {} }: ScopeRulesTableProps) {
  const rows = Object.entries(labels)
    .map(([key, label]) => ({ key, label, values: Array.isArray(rules[key]) ? rules[key] as string[] : [] }))
    .filter((row) => row.values.length > 0)

  return (
    <div className="scope-rules">
      <h3>{title}</h3>
      {rows.length ? (
        <table className="data-table">
          <thead>
            <tr>
              <th>Rule type</th>
              <th>Values</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.key}>
                <td>{row.label}</td>
                <td>{row.values.join(', ')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div className="empty-state">No rules configured.</div>
      )}
    </div>
  )
}
