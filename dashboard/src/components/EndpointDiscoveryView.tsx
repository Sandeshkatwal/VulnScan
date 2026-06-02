import { useEffect, useMemo, useState } from 'react'
import { analyseEndpoints, getBugBountyScopes } from '../api/client'
import type { BugBountyScopeSummary, EndpointDiscoveryResponse } from '../types/api'
import { EndpointCandidatePanel } from './EndpointCandidatePanel'
import { EndpointImportPanel } from './EndpointImportPanel'
import { EndpointSummaryCards } from './EndpointSummaryCards'
import { EndpointTable } from './EndpointTable'
import { ErrorAlert } from './ErrorAlert'
import { ParameterIntelligenceTable } from './ParameterIntelligenceTable'

interface EndpointDiscoveryViewProps {
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

const sampleUrls = [
  'http://127.0.0.1:8000/login',
  'http://127.0.0.1:8000/admin',
  'http://127.0.0.1:8000/api/users/123',
  'http://127.0.0.1:8000/account?id=123',
  'http://127.0.0.1:8000/redirect?next=/dashboard',
  'http://127.0.0.1:8000/download?file=report.pdf',
  'http://127.0.0.1:8000/search?q=test',
  'http://127.0.0.1:8000/reset-password?token=demo',
  '/uploads',
  '/api/v1/orders',
].join('\n')

const demoResult: EndpointDiscoveryResponse = {
  endpoint_discovery: {
    enabled: true,
    program_name: 'Demo Program Scope',
    input_urls_count: 4,
    in_scope_urls_count: 4,
    out_of_scope_urls_count: 0,
    endpoints_with_parameters_count: 3,
    interesting_parameters_count: 3,
    high_interest_count: 1,
    medium_interest_count: 2,
    low_interest_count: 1,
  },
  endpoint_results: [
    {
      normalised_url: 'http://127.0.0.1:8000/reset-password?token=REDACTED',
      path: '/reset-password',
      parameters: [{ name: 'token', value_redacted: true }],
      endpoint_category: 'password_reset',
      candidate_score: 70,
      candidate_label: 'High Interest',
      candidate_reasons: ['Authentication or password reset endpoint', 'Sensitive token parameter: token', 'In scope'],
      in_scope: true,
    },
  ],
  parameter_results: [
    {
      path: '/account',
      parameter_name: 'id',
      parameter_type: 'idor',
      potential_issue: 'IDOR Candidate',
      confidence: 'Medium',
      manual_validation_note: 'Manual validation required. Parameter candidates are not confirmed vulnerabilities.',
    },
  ],
  endpoint_skipped: [],
  findings: [],
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Endpoint discovery request failed.'
}

export function EndpointDiscoveryView({ apiOnline, demoMode = false }: EndpointDiscoveryViewProps) {
  const [scopes, setScopes] = useState<BugBountyScopeSummary[]>(demoMode ? demoScopes : [])
  const [scopeFile, setScopeFile] = useState(demoScopes[0]?.scope_file || '')
  const [urls, setUrls] = useState(sampleUrls)
  const [baseUrl, setBaseUrl] = useState('http://127.0.0.1:8000')
  const [enforceScope, setEnforceScope] = useState(true)
  const [result, setResult] = useState<EndpointDiscoveryResponse | null>(demoMode ? demoResult : null)
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

  const urlList = useMemo(
    () => urls.split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
    [urls],
  )

  async function startAnalysis() {
    if (demoMode) {
      setResult(demoResult)
      return
    }
    setLoading(true)
    setError(null)
    try {
      setResult(await analyseEndpoints({
        urls: urlList,
        base_url: baseUrl || undefined,
        scope_file: scopeFile || undefined,
        enforce_scope: enforceScope,
      }))
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="content-grid">
      <article className="panel">
        <div className="panel-heading">
          <h2>Endpoint Input</h2>
          <p>Analyse supplied endpoints and parameter names without sending requests.</p>
        </div>
        <ErrorAlert message={error} />
        <div className="recon-form">
          <EndpointImportPanel value={urls} disabled={loading} onChange={setUrls} />
          <label>
            <span>Base URL</span>
            <input value={baseUrl} disabled={loading} onChange={(event) => setBaseUrl(event.target.value)} />
          </label>
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
            <small>Out-of-scope URLs are skipped before candidate scoring.</small>
          </label>
          <button className="primary-button" type="button" disabled={loading || !urlList.length} onClick={() => void startAnalysis()}>
            {loading ? 'Analysing...' : 'Analyse Endpoints'}
          </button>
        </div>
      </article>

      <article className="panel">
        <div className="panel-heading">
          <h2>Summary</h2>
          <p>Candidate scoring is heuristic and requires manual validation.</p>
        </div>
        <EndpointSummaryCards summary={result?.endpoint_discovery} />
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>Endpoint Candidates</h2>
          <p>Labels show Candidate status only.</p>
        </div>
        <EndpointTable results={result?.endpoint_results || []} />
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>Parameter Intelligence</h2>
          <p>Parameter candidates are not confirmed vulnerabilities.</p>
        </div>
        <ParameterIntelligenceTable results={result?.parameter_results || []} />
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>Manual Validation Required</h2>
          <p>Review findings and skipped URLs before any authorised manual testing.</p>
        </div>
        <EndpointCandidatePanel skipped={result?.endpoint_skipped || []} findings={result?.findings || []} />
      </article>
    </section>
  )
}
