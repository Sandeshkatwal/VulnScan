export function RegressionStatusPanel() {
  return (
    <article className="panel">
      <div className="panel-heading">
        <h2>Regression Status</h2>
        <p>Version 22.1 Bug Fix Sprint checks.</p>
      </div>
      <div className="beta-status-grid">
        <div><span>Focus</span><strong>Regression Test Hardening</strong></div>
        <div><span>Mode</span><strong>Safe Regression Testing</strong></div>
        <div><span>Scope</span><strong>CLI, API, Reports, Demo, Security</strong></div>
        <div><span>Release</span><strong>22.1.0-beta</strong></div>
      </div>
    </article>
  )
}
