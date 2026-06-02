import { useEffect, useMemo, useState } from 'react'
import { getBugBountyScopes, runBugBountyRecon } from '../api/client'
import type { BugBountyReconResponse, BugBountyScopeSummary } from '../types/api'
import { ErrorAlert } from './ErrorAlert'
import { ReconFindingPanel } from './ReconFindingPanel'
import { ReconResultsTable } from './ReconResultsTable'
import { ReconSummaryCards } from './ReconSummaryCards'
import { ReconTargetImport } from './ReconTargetImport'

interface BugBountyReconViewProps {
  apiOnline: boolean
  demoMode?: boolean
}

const demoScopes: BugBountyScopeSummary[] = [
  {
    program_id: 'demo-program-scope',
    program_name: 'Demo Program Scope',
    platform: 'local-demo',
    scope_file: 'data/programs/sample_program_scope.json',
  },
]

const demoResult: BugBountyReconResponse = {
  bug_bounty_recon: {
    enabled: true,
    program_name: 'Demo Program Scope',
    input_targets_count: 3,
    in_scope_targets_count: 2,
    out_of_scope_targets_count: 1,
    probed_count: 2,
    live_count: 1,
    error_count: 0,
    skipped_count: 1,
    technologies_observed: ['nginx'],
  },
  bug_bounty_recon_results: [
    {
      target: '127.0.0.1',
      target_type: 'ip',
      probe_url: 'http://127.0.0.1:8000/',
      final_url: 'http://127.0.0.1:8000/',
      status_code: 200,
      live: true,
      page_title: 'Demo Local App',
      server_header: 'nginx',
      response_time_ms: 42,
      in_scope: true,
      technology_hints: [{ name: 'nginx', source: 'server_header', confidence: 'Medium' }],
    },
  ],
  bug_bounty_recon_skipped: [
    {
      target: 'payments.demo-web.local',
      probe_url: 'https://payments.demo-web.local',
      reason: 'Out-of-scope target skipped.',
      scope_reason: 'Matched out-of-scope domain.',
    },
  ],
  findings: [],
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Recon intelligence request failed.'
}

export function BugBountyReconView({ apiOnline, demoMode = false }: BugBountyReconViewProps) {
  const [scopes, setScopes] = useState<BugBountyScopeSummary[]>(demoMode ? demoScopes : [])
  const [scopeFile, setScopeFile] = useState(demoScopes[0]?.scope_file || '')
  const [targets, setTargets] = useState('127.0.0.1\nhttp://127.0.0.1:8000/')
  const [enforceScope, setEnforceScope] = useState(true)
  const [requestDelay, setRequestDelay] = useState(1)
  const [timeout, setTimeoutValue] = useState(5)
  const [maxRequestsPerMinute, setMaxRequestsPerMinute] = useState(30)
  const [result, setResult] = useState<BugBountyReconResponse | null>(demoMode ? demoResult : null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (demoMode) {
      setScopes(demoScopes)
      setScopeFile(demoScopes[0]?.scope_file || '')
      setResult(demoResult)
      return
    }
    if (!apiOnline) return
    getBugBountyScopes()
      .then((response) => {
        setScopes(response.scopes)
        setScopeFile(response.scopes[0]?.scope_file || '')
      })
      .catch((caught) => setError(errorMessage(caught)))
  }, [apiOnline, demoMode])

  const targetList = useMemo(
    () => targets.split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
    [targets],
  )

  async function startRecon() {
    if (demoMode) {
      setResult(demoResult)
      return
    }
    setLoading(true)
    setError(null)
    try {
      setResult(await runBugBountyRecon({
        targets: targetList,
        scope_file: scopeFile || undefined,
        enforce_scope: enforceScope,
        request_delay: requestDelay,
        max_requests_per_minute: maxRequestsPerMinute,
        timeout,
        max_redirects: 5,
      }))
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  const summary = result?.bug_bounty_recon
  const results = result?.bug_bounty_recon_results || []
  const skipped = result?.bug_bounty_recon_skipped || []
  const findings = result?.findings || []

  return (
    <section className="content-grid">
      <article className="panel">
        <div className="panel-heading">
          <h2>Recon Input</h2>
          <p>Import known authorised targets and probe HTTP/HTTPS gently.</p>
        </div>
        <ErrorAlert message={error} />
        {!scopeFile ? <div className="panel-message panel-message--error">Use only on assets you are authorised to test.</div> : null}
        <div className="recon-form">
          <ReconTargetImport value={targets} disabled={loading} onChange={setTargets} />
          <label>
            <span>Scope</span>
            <select value={scopeFile} disabled={loading} onChange={(event) => setScopeFile(event.target.value)}>
              <option value="">No local scope selected</option>
              {scopes.map((scope) => (
                <option key={scope.scope_file || scope.program_id} value={scope.scope_file || ''}>
                  {scope.program_name || scope.program_id || scope.scope_file}
                </option>
              ))}
            </select>
          </label>
          <label className="demo-mode-toggle">
            <input type="checkbox" checked={enforceScope} disabled={loading} onChange={(event) => setEnforceScope(event.target.checked)} />
            <span>Enforce scope</span>
            <small>Out-of-scope targets are skipped before probing.</small>
          </label>
          <div className="recon-options-grid">
            <label>
              <span>Delay</span>
              <input type="number" min="0" max="30" step="0.5" value={requestDelay} disabled={loading} onChange={(event) => setRequestDelay(Number(event.target.value))} />
            </label>
            <label>
              <span>Timeout</span>
              <input type="number" min="1" max="30" step="1" value={timeout} disabled={loading} onChange={(event) => setTimeoutValue(Number(event.target.value))} />
            </label>
            <label>
              <span>Max RPM</span>
              <input type="number" min="1" max="120" step="1" value={maxRequestsPerMinute} disabled={loading} onChange={(event) => setMaxRequestsPerMinute(Number(event.target.value))} />
            </label>
          </div>
          <button className="primary-button" type="button" disabled={loading || !targetList.length} onClick={() => void startRecon()}>
            {loading ? 'Running...' : 'Start Recon'}
          </button>
        </div>
      </article>

      <article className="panel">
        <div className="panel-heading">
          <h2>Summary</h2>
          <p>Metadata-only recon results for provided targets.</p>
        </div>
        <ReconSummaryCards summary={summary} />
        <ReconFindingPanel findings={findings} />
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>Results</h2>
          <p>No response bodies, cookies, tokens, passwords, or private keys are stored.</p>
        </div>
        <ReconResultsTable results={results} skipped={skipped} />
      </article>
    </section>
  )
}
