import { useEffect, useState } from 'react'
import { getBugBountyScopes, runSafeValidation } from '../api/client'
import type { BugBountyScopeSummary, SafeValidationResponse, SafeValidationResult } from '../types/api'
import { ErrorAlert } from './ErrorAlert'
import { ValidationChecksSelector } from './ValidationChecksSelector'
import { ValidationEvidencePanel } from './ValidationEvidencePanel'
import { ValidationResultsTable } from './ValidationResultsTable'
import { ValidationSafetyNotice } from './ValidationSafetyNotice'
import { ValidationSummaryCards } from './ValidationSummaryCards'
import { ValidationTargetInput } from './ValidationTargetInput'

interface SafeValidationViewProps {
  apiOnline: boolean
  demoMode?: boolean
}

const checks = ['reflected_input_observation', 'open_redirect_indicator', 'cors_indicator', 'directory_listing_indicator', 'default_file_exposure_indicator', 'http_methods_indicator']

const demoScopes: BugBountyScopeSummary[] = [{ program_id: 'demo-program-scope', program_name: 'Demo Program Scope', scope_file: 'data/programs/sample_program_scope.json' }]

const demoResult: SafeValidationResponse = {
  safe_active_validation: { enabled: true, input_targets_count: 1, in_scope_targets_count: 1, checks_run: 1, checks_skipped: 0, indicators_found: 1, request_count: 1, rate_limit_applied: true },
  safe_active_validation_results: [{
    url: 'http://127.0.0.1:8000/search?q=test',
    candidate_type: 'reflected_input',
    parameter: 'q',
    check_name: 'reflected_input_observation',
    status: 'checked',
    indicator_found: true,
    confidence: 'Medium',
    evidence_summary: { marker_reflected: true, reflection_context: 'html_text' },
    request_method: 'GET',
    manual_validation_note: 'Indicator only. Manual validation required. No exploitability confirmed.',
  }],
  safe_active_validation_skipped: [],
  findings: [],
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Safe validation request failed.'
}

export function SafeValidationView({ apiOnline, demoMode = false }: SafeValidationViewProps) {
  const [scopes, setScopes] = useState<BugBountyScopeSummary[]>(demoMode ? demoScopes : [])
  const [scopeFile, setScopeFile] = useState(demoScopes[0]?.scope_file || '')
  const [url, setUrl] = useState('http://127.0.0.1:8000/search?q=test')
  const [candidateType, setCandidateType] = useState('reflected_input')
  const [parameter, setParameter] = useState('q')
  const [selectedChecks, setSelectedChecks] = useState<string[]>(checks)
  const [enforceScope, setEnforceScope] = useState(true)
  const [requestDelay, setRequestDelay] = useState(1)
  const [timeout, setTimeoutValue] = useState(5)
  const [result, setResult] = useState<SafeValidationResponse | null>(demoMode ? demoResult : null)
  const [selectedResult, setSelectedResult] = useState<SafeValidationResult | null>(demoResult.safe_active_validation_results?.[0] || null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (demoMode) {
      setScopes(demoScopes)
      setResult(demoResult)
      return
    }
    if (!apiOnline) return
    getBugBountyScopes().then((response) => {
      setScopes(response.scopes)
      setScopeFile(response.scopes[0]?.scope_file || '')
    }).catch((caught) => setError(errorMessage(caught)))
  }, [apiOnline, demoMode])

  async function startValidation() {
    if (demoMode) {
      setResult(demoResult)
      return
    }
    setLoading(true)
    setError(null)
    try {
      const response = await runSafeValidation({
        targets: [{ url, candidate_type: candidateType, parameter: parameter || undefined, source: 'dashboard' }],
        scope_file: scopeFile || undefined,
        enforce_scope: enforceScope,
        checks: selectedChecks,
        request_delay: requestDelay,
        timeout,
        max_requests_per_minute: 20,
        max_validation_requests: 20,
        safe_active_confirm: true,
      })
      setResult(response)
      setSelectedResult(response.safe_active_validation_results?.[0] || null)
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  const summary = result?.safe_active_validation
  return (
    <section className="content-grid">
      <article className="panel panel--wide">
        <div className="panel-heading"><h2>Safe Validation</h2><p>Limited non-destructive checks for authorised in-scope URLs.</p></div>
        <ValidationSafetyNotice />
        <ErrorAlert message={error} />
        <div className="recon-form">
          <ValidationTargetInput url={url} candidateType={candidateType} parameter={parameter} disabled={loading} onUrlChange={setUrl} onCandidateTypeChange={setCandidateType} onParameterChange={setParameter} />
          <ValidationChecksSelector selected={selectedChecks} disabled={loading} onChange={setSelectedChecks} />
          <label><span>Scope</span><select value={scopeFile} disabled={loading} onChange={(event) => setScopeFile(event.target.value)}><option value="">No local scope selected</option>{scopes.map((scope) => <option key={scope.scope_file || scope.program_id} value={scope.scope_file || ''}>{scope.program_name || scope.program_id}</option>)}</select></label>
          <label className="demo-mode-toggle"><input type="checkbox" checked={enforceScope} disabled={loading} onChange={(event) => setEnforceScope(event.target.checked)} /><span>Enforce scope</span></label>
          <div className="recon-options-grid">
            <label><span>Delay</span><input type="number" min="0" max="30" step="0.5" value={requestDelay} disabled={loading} onChange={(event) => setRequestDelay(Number(event.target.value))} /></label>
            <label><span>Timeout</span><input type="number" min="1" max="30" step="1" value={timeout} disabled={loading} onChange={(event) => setTimeoutValue(Number(event.target.value))} /></label>
          </div>
          <button className="primary-button" type="button" disabled={loading || !url || !selectedChecks.length} onClick={() => void startValidation()}>{loading ? 'Running...' : 'Run Safe Validation'}</button>
        </div>
      </article>
      <article className="panel panel--wide"><div className="panel-heading"><h2>Summary</h2><p>Indicator only. Manual validation required.</p></div><ValidationSummaryCards summary={summary} /></article>
      <article className="panel panel--wide"><div className="panel-heading"><h2>Results</h2><p>No response bodies, cookies, tokens, passwords, or private keys are stored.</p></div><ValidationResultsTable results={result?.safe_active_validation_results || []} skipped={result?.safe_active_validation_skipped || []} onSelectResult={setSelectedResult} /></article>
      <article className="panel panel--wide"><div className="panel-heading"><h2>Evidence Summary</h2><p>Observed behaviour only.</p></div><ValidationEvidencePanel result={selectedResult} /></article>
    </section>
  )
}
