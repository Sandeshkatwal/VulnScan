const blocks = [
  ['Discovery Engine', 'Implemented'],
  ['Credentialed Scan Engine', 'Implemented'],
  ['Web DAST Engine', 'Foundation'],
  ['Vulnerability Intelligence Engine', 'Implemented'],
  ['Prioritisation Engine', 'Implemented'],
  ['Storage', 'Implemented'],
  ['API', 'Implemented'],
  ['Dashboard', 'In progress'],
]

export function ArchitectureSummary() {
  return (
    <section className="architecture-summary">
      <div className="panel-heading">
        <h2>Architecture Summary</h2>
        <p>Local modules backing the dashboard and reporting workflow.</p>
      </div>
      <div className="architecture-grid">
        {blocks.map(([name, status]) => (
          <div className="architecture-block" key={name}>
            <strong>{name}</strong>
            <span>{status}</span>
          </div>
        ))}
      </div>
    </section>
  )
}
