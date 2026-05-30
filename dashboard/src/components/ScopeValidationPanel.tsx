import { useState } from 'react'
import { checkBugBountyScope } from '../api/client'
import type { BugBountyScopeSummary, ScopeCheckResponse } from '../types/api'
import { ScopeBadge } from './ScopeBadge'

interface ScopeValidationPanelProps {
  scopes: BugBountyScopeSummary[]
  selectedScope?: BugBountyScopeSummary | null
  demoMode?: boolean
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Scope check failed.'
}

export function ScopeValidationPanel({ scopes, selectedScope, demoMode = false }: ScopeValidationPanelProps) {
  const [target, setTarget] = useState('https://demo-web.local/')
  const [scopeFile, setScopeFile] = useState(selectedScope?.scope_file || scopes[0]?.scope_file || '')
  const [result, setResult] = useState<ScopeCheckResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function handleCheck() {
    setError(null)
    setResult(null)
    if (!target.trim() || !scopeFile) {
      setError('Select a scope file and enter a target or URL.')
      return
    }
    if (demoMode) {
      const inScope = target.includes('demo-web.local') || target.includes('127.0.0.1')
      setResult({
        target,
        in_scope: inScope,
        reason: inScope ? 'Demo target matched local demo scope.' : 'Demo target is outside local demo scope.',
        matched_rule: inScope ? 'demo-web.local / 127.0.0.1' : '',
        program_name: selectedScope?.program_name || 'Demo Bug Bounty Program',
      })
      return
    }
    setLoading(true)
    try {
      setResult(await checkBugBountyScope({ target, scope_file: scopeFile }))
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="scope-validation">
      <div className="form-field">
        <label htmlFor="scope-target">Target or URL</label>
        <input id="scope-target" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://demo-web.local/" />
      </div>
      <div className="form-field">
        <label htmlFor="scope-file">Scope file</label>
        <select id="scope-file" value={scopeFile} onChange={(event) => setScopeFile(event.target.value)}>
          {scopes.map((scope) => (
            <option key={scope.scope_file || scope.program_id} value={scope.scope_file || ''}>
              {scope.program_name || scope.program_id}
            </option>
          ))}
        </select>
      </div>
      <div className="button-row">
        <button className="primary-button" type="button" onClick={() => void handleCheck()} disabled={loading}>
          {loading ? 'Checking...' : 'Check Scope'}
        </button>
      </div>
      {error ? <div className="error-alert">{error}</div> : null}
      {result ? (
        <div className={result.in_scope ? 'scope-result scope-result--in' : 'scope-result scope-result--out'}>
          <ScopeBadge inScope={Boolean(result.in_scope)} />
          <p>{result.reason}</p>
          <p><strong>Matched rule:</strong> {result.matched_rule || 'None'}</p>
          {!result.in_scope ? <p className="scope-warning">Do not test targets that are outside the configured program scope.</p> : null}
        </div>
      ) : null}
    </div>
  )
}
