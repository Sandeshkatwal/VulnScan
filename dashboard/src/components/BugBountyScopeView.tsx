import { useEffect, useState } from 'react'
import { getBugBountyScope, getBugBountyScopes } from '../api/client'
import type { BugBountyScopeDetail, BugBountyScopeSummary } from '../types/api'
import { ErrorAlert } from './ErrorAlert'
import { ScopeProgramCard } from './ScopeProgramCard'
import { ScopeRulesTable } from './ScopeRulesTable'
import { ScopeValidationPanel } from './ScopeValidationPanel'

interface BugBountyScopeViewProps {
  apiOnline: boolean
  demoMode?: boolean
}

const demoScope: BugBountyScopeSummary = {
  program_id: 'demo-program-scope',
  program_name: 'Demo Program Scope',
  platform: 'local-demo',
  policy_url: 'local-only',
  scope_version: '1.0',
  last_updated: 'demo-local',
  scope_file: 'data/programs/sample_program_scope.json',
}

const demoDetail: BugBountyScopeDetail = {
  metadata: demoScope,
  scope: {
    ...demoScope,
    in_scope: {
      domains: ['demo-web.local', '*.demo-web.local', '127.0.0.1'],
      urls: ['http://127.0.0.1:8000/', 'https://demo-web.local/'],
      api_base_urls: ['https://api.demo-web.local/'],
      ip_ranges: ['127.0.0.1/32'],
    },
    out_of_scope: {
      domains: ['payments.demo-web.local', 'auth.thirdparty.local'],
      urls: ['https://demo-web.local/logout', 'https://demo-web.local/admin/delete'],
      ip_ranges: [],
    },
    forbidden_actions: ['denial_of_service', 'brute_force', 'credential_stuffing', 'social_engineering', 'data_destruction'],
    allowed_test_types: ['passive_recon', 'passive_web_dast', 'safe_header_checks', 'safe_cookie_checks', 'safe_form_discovery', 'manual_validation'],
    disallowed_test_types: ['automated_exploitation', 'destructive_testing', 'credential_attacks', 'dos_testing'],
    rate_limits: { max_requests_per_minute: 30, request_delay_seconds: 1.0, max_pages: 50, max_depth: 2 },
    notes: ['This is demo scope data only.', 'Always verify scope against the real program policy before testing.'],
  },
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Program scope request failed.'
}

export function BugBountyScopeView({ apiOnline, demoMode = false }: BugBountyScopeViewProps) {
  const [scopes, setScopes] = useState<BugBountyScopeSummary[]>(demoMode ? [demoScope] : [])
  const [selected, setSelected] = useState<BugBountyScopeSummary | null>(demoMode ? demoScope : null)
  const [detail, setDetail] = useState<BugBountyScopeDetail | null>(demoMode ? demoDetail : null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (demoMode) {
      setScopes([demoScope])
      setSelected(demoScope)
      setDetail(demoDetail)
      return
    }
    if (!apiOnline) return
    setLoading(true)
    setError(null)
    getBugBountyScopes()
      .then((response) => {
        setScopes(response.scopes)
        const first = response.scopes[0] || null
        setSelected(first)
        if (first?.program_id) return getBugBountyScope(first.program_id)
        return null
      })
      .then((scopeDetail) => {
        if (scopeDetail) setDetail(scopeDetail)
      })
      .catch((caught) => setError(errorMessage(caught)))
      .finally(() => setLoading(false))
  }, [apiOnline, demoMode])

  async function selectScope(scope: BugBountyScopeSummary) {
    setSelected(scope)
    setError(null)
    if (demoMode) {
      setDetail(demoDetail)
      return
    }
    if (!scope.program_id) return
    setLoading(true)
    try {
      setDetail(await getBugBountyScope(scope.program_id))
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  const scope = detail?.scope

  return (
    <section className="content-grid">
      <article className="panel">
        <div className="panel-heading">
          <h2>Programs</h2>
          <p>Local Program Scope files under data/programs, with legacy data/bug_bounty compatibility.</p>
        </div>
        <ErrorAlert message={error} />
        {loading ? <div className="empty-state">Loading scope files...</div> : null}
        <div className="scope-program-list">
          {scopes.map((scopeItem) => (
            <ScopeProgramCard
              key={scopeItem.program_id || scopeItem.scope_file}
              scope={scopeItem}
              selected={scopeItem.program_id === selected?.program_id}
              onSelect={(nextScope) => void selectScope(nextScope)}
            />
          ))}
        </div>
        {!scopes.length && !loading ? <div className="empty-state">No local program scope files were found.</div> : null}
      </article>

      <article className="panel">
        <div className="panel-heading">
          <h2>Scope Validation</h2>
          <p>Check a target against the selected local program scope.</p>
        </div>
        <ScopeValidationPanel scopes={scopes} selectedScope={selected} demoMode={demoMode} />
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>Program Scope</h2>
          <p>Always verify the live program policy before testing.</p>
        </div>
        {scope ? (
          <>
            <ScopeRulesTable title="In Scope" rules={scope.in_scope} />
            <ScopeRulesTable title="Out of Scope" rules={scope.out_of_scope} />
            <div className="scope-roE-grid">
              <div>
                <h3>Forbidden Actions</h3>
                <p>{(scope.forbidden_actions || []).join(', ') || 'None listed'}</p>
              </div>
              <div>
                <h3>Allowed Test Types</h3>
                <p>{(scope.allowed_test_types || []).join(', ') || 'None listed'}</p>
              </div>
              <div>
                <h3>Disallowed Test Types</h3>
                <p>{(scope.disallowed_test_types || []).join(', ') || 'None listed'}</p>
              </div>
              <div>
                <h3>Rate Limits</h3>
                <p>{Object.entries(scope.rate_limits || {}).map(([key, value]) => `${key}: ${String(value)}`).join(', ') || 'None listed'}</p>
              </div>
            </div>
          </>
        ) : (
          <div className="empty-state">Select a local scope file to review rules.</div>
        )}
      </article>
    </section>
  )
}
