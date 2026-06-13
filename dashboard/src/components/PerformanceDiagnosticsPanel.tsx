import type { DiagnosticsResponse } from '../types/api'

interface Props {
  diagnostics?: DiagnosticsResponse | null
}

export function PerformanceDiagnosticsPanel({ diagnostics }: Props) {
  const performance = diagnostics?.performance as Record<string, unknown> | undefined
  const counts = performance?.record_counts as Record<string, unknown> | undefined
  return (
    <article className="panel">
      <div className="panel-heading">
        <h2>Performance Diagnostics</h2>
        <p>Local counts, size estimates, and baseline path.</p>
      </div>
      <dl className="diagnostics-grid">
        <div><dt>Finding files</dt><dd>{String(counts?.finding_files ?? 0)}</dd></div>
        <div><dt>Evidence files</dt><dd>{String(counts?.evidence_files ?? 0)}</dd></div>
        <div><dt>Report files</dt><dd>{String(counts?.report_files ?? 0)}</dd></div>
        <div><dt>Baseline</dt><dd>{String(performance?.performance_baseline_path ?? 'reports/performance/performance_baseline.json')}</dd></div>
      </dl>
    </article>
  )
}
