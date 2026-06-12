import { useEffect, useState } from 'react'
import { getDiagnostics } from '../api/client'
import type { DiagnosticsResponse } from '../types/api'

interface DiagnosticsPanelProps {
  apiOnline: boolean
}

export function DiagnosticsPanel({ apiOnline }: DiagnosticsPanelProps) {
  const [diagnostics, setDiagnostics] = useState<DiagnosticsResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!apiOnline) return
    setLoading(true)
    getDiagnostics()
      .then((result) => {
        setDiagnostics(result)
        setError(null)
      })
      .catch((err: unknown) => setError(err instanceof Error ? err.message : 'Diagnostics unavailable.'))
      .finally(() => setLoading(false))
  }, [apiOnline])

  const warnings = diagnostics?.warnings || []
  const failed = diagnostics?.summary?.failed_checks || []

  return (
    <article className="panel panel--wide">
      <div className="panel-heading">
        <h2>Diagnostics</h2>
        <p>Safe diagnostics without environment variables, auth profiles, cookies, or tokens.</p>
      </div>
      {!apiOnline ? <div className="empty-state">Diagnostics are unavailable while the local API is offline. Demo mode remains available.</div> : null}
      {loading ? <div className="empty-state">Loading diagnostics...</div> : null}
      {error ? <div className="empty-state">{error}</div> : null}
      {diagnostics ? (
        <>
          <div className="beta-status-grid">
            <div><span>Summary</span><strong>{diagnostics.summary?.status || 'unknown'}</strong></div>
            <div><span>Warnings</span><strong>{warnings.length}</strong></div>
            <div><span>Failed checks</span><strong>{failed.length}</strong></div>
            <div><span>Secret dump</span><strong>{diagnostics.safety_checks?.secret_values_dumped ? 'Review' : 'Disabled'}</strong></div>
          </div>
          <ul className="beta-list">
            {[...warnings, ...failed].slice(0, 8).map((item) => <li key={item}>{item}</li>)}
          </ul>
        </>
      ) : null}
    </article>
  )
}
