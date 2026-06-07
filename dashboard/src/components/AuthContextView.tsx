import { useEffect, useMemo, useState } from 'react'
import { checkAuthBoundary, classifyAuthEndpoints, getAuthProfiles, runAuthenticatedCrawl } from '../api/client'
import type { AuthBoundaryResult, AuthenticatedCrawlResponse, SessionProfileSummary, JobResultResponse } from '../types/api'
import { ErrorAlert } from './ErrorAlert'

interface AuthContextViewProps {
  apiOnline: boolean
  demoMode?: boolean
  jobResult?: JobResultResponse | null
}

const demoProfiles: SessionProfileSummary[] = [{
  profile_id: 'demo_authenticated_user',
  profile_name: 'Demo authenticated user',
  target_base_url: 'http://127.0.0.1:8000',
  auth_type: 'cookie',
  role_label: 'standard_user',
  redaction_status: 'redacted',
  cookie_names: ['sessionid'],
  header_names: ['Authorization'],
  allowed_hosts: ['127.0.0.1'],
  allowed_paths: ['/'],
  blocked_paths: ['/logout', '/delete', '/admin/delete', '/payment'],
  permission_notes: 'Demo profile only. Do not store real secrets in repository.',
  local_only: true,
}]

export function AuthContextView({ apiOnline, demoMode = false, jobResult }: AuthContextViewProps) {
  const [profiles, setProfiles] = useState<SessionProfileSummary[]>(demoMode ? demoProfiles : [])
  const [selectedId, setSelectedId] = useState(demoProfiles[0]?.profile_id || '')
  const [url, setUrl] = useState('http://127.0.0.1:8000/dashboard')
  const [boundary, setBoundary] = useState<AuthBoundaryResult | null>(demoMode ? { url: 'http://127.0.0.1:8000/dashboard', allowed_by_profile: true, blocked_by_profile: false, reason: 'URL is inside the Authenticated Scope.', role_label: 'standard_user' } : null)
  const [classified, setClassified] = useState<Array<Record<string, unknown>>>([])
  const [crawlUrl, setCrawlUrl] = useState('http://127.0.0.1:8000/dashboard')
  const [maxPages, setMaxPages] = useState(30)
  const [maxDepth, setMaxDepth] = useState(2)
  const [requestDelay, setRequestDelay] = useState(1)
  const [sameOriginOnly, setSameOriginOnly] = useState(true)
  const [dryRun, setDryRun] = useState(true)
  const [crawlResult, setCrawlResult] = useState<AuthenticatedCrawlResponse | null>(demoMode ? demoCrawlResult() : null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (demoMode) {
      setProfiles(demoProfiles)
      setSelectedId(demoProfiles[0].profile_id || '')
      setClassified(demoClassifiedEndpoints())
      setCrawlResult(demoCrawlResult())
      return
    }
    if (!apiOnline) return
    getAuthProfiles().then((response) => {
      setProfiles(response.profiles || [])
      setSelectedId((response.profiles || [])[0]?.profile_id || '')
    }).catch((caught) => setError(errorMessage(caught)))
  }, [apiOnline, demoMode])

  const selected = useMemo(() => profiles.find((profile) => profile.profile_id === selectedId) || profiles[0], [profiles, selectedId])
  const resultPayload = jobResult?.result as Record<string, unknown> | null | undefined
  const endpointResults = (resultPayload?.endpoint_results as Array<Record<string, unknown>> | undefined) || []

  async function runBoundaryCheck() {
    if (!selected) return
    setLoading(true)
    setError(null)
    try {
      setBoundary(await checkAuthBoundary(selected as Record<string, unknown>, url))
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  async function runEndpointClassification() {
    if (!selected) return
    setLoading(true)
    setError(null)
    try {
      if (demoMode && !endpointResults.length) {
        setClassified(demoClassifiedEndpoints())
      } else {
        const response = await classifyAuthEndpoints(selected as Record<string, unknown>, endpointResults)
        setClassified(response.classified_endpoints || [])
      }
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  async function startAuthenticatedCrawl() {
    if (!selected) return
    setLoading(true)
    setError(null)
    try {
      if (demoMode) {
        setCrawlResult(demoCrawlResult())
      } else {
        setCrawlResult(await runAuthenticatedCrawl({
          url: crawlUrl,
          profile: selected as Record<string, unknown>,
          max_pages: maxPages,
          max_depth: maxDepth,
          request_delay: requestDelay,
          timeout: 5,
          same_origin_only: sameOriginOnly,
          dry_run: dryRun,
        }))
      }
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="content-grid">
      <article className="panel panel--wide">
        <div className="panel-heading">
          <div>
            <h2>Authenticated Assessment</h2>
            <p>Session Profile, Authentication Context, Authenticated Scope, and Auth-Required Endpoint classification.</p>
          </div>
        </div>
        <div className="auth-safety-notice">
          Authenticated assessment requires explicit authorisation. Do not store real credentials in the repository. VulScan redacts auth material from UI, reports, and logs.
        </div>
        <ErrorAlert message={error} />
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading"><h2>Session Profiles</h2><p>Safe summaries only. Cookie and header values are never shown.</p></div>
        <div className="table-shell">
          <table>
            <thead><tr><th>Profile</th><th>Target</th><th>Auth Type</th><th>Role</th><th>Redaction</th><th>Updated</th></tr></thead>
            <tbody>{profiles.map((profile) => (
              <tr key={profile.profile_id} onClick={() => setSelectedId(profile.profile_id || '')}>
                <td>{profile.profile_name}</td><td>{profile.target_base_url}</td><td>{profile.auth_type}</td><td>{profile.role_label}</td><td><RedactionBadge status={profile.redaction_status} /></td><td>{profile.updated_at || 'Not set'}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading"><h2>Profile Detail</h2><p>Names and boundaries only. No raw auth headers, cookies, tokens, or passwords.</p></div>
        {selected ? <ProfileDetail profile={selected} /> : <div className="panel-message">No Session Profile selected.</div>}
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading"><h2>Boundary Checker</h2><p>Blocked paths override allowed paths.</p></div>
        <div className="auth-boundary-form">
          <select value={selectedId} onChange={(event) => setSelectedId(event.target.value)}>
            {profiles.map((profile) => <option key={profile.profile_id} value={profile.profile_id}>{profile.profile_name}</option>)}
          </select>
          <input value={url} onChange={(event) => setUrl(event.target.value)} placeholder="http://127.0.0.1:8000/dashboard" />
          <button className="primary-button" disabled={!selected || loading} onClick={() => void runBoundaryCheck()} type="button">Check URL</button>
        </div>
        {boundary && <div className="auth-boundary-result"><strong>{boundary.allowed_by_profile ? 'Allowed' : 'Blocked'}</strong><span>{boundary.reason}</span><small>{boundary.url}</small></div>}
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading">
          <div><h2>Authenticated Crawl</h2><p>GET-only crawl with Session Boundary Controls and Redacted Authenticated Evidence.</p></div>
          <button className="primary-button" type="button" disabled={!selected || loading} onClick={() => void startAuthenticatedCrawl()}>Start Authenticated Crawl</button>
        </div>
        <div className="auth-safety-notice">
          Authenticated crawl uses provided session context only for authorised testing. It uses GET-only requests, does not submit forms, and blocks logout/delete/payment/destructive paths.
        </div>
        <div className="auth-crawl-config">
          <label><span>Start URL</span><input value={crawlUrl} onChange={(event) => setCrawlUrl(event.target.value)} /></label>
          <label><span>Max pages</span><input type="number" min={1} max={200} value={maxPages} onChange={(event) => setMaxPages(Number(event.target.value))} /></label>
          <label><span>Max depth</span><input type="number" min={0} max={10} value={maxDepth} onChange={(event) => setMaxDepth(Number(event.target.value))} /></label>
          <label><span>Request delay</span><input type="number" min={0} max={30} step={0.5} value={requestDelay} onChange={(event) => setRequestDelay(Number(event.target.value))} /></label>
          <label className="checkbox-row"><input type="checkbox" checked={sameOriginOnly} onChange={(event) => setSameOriginOnly(event.target.checked)} /> Same origin only</label>
          <label className="checkbox-row"><input type="checkbox" checked={dryRun} onChange={(event) => setDryRun(event.target.checked)} /> Dry run</label>
        </div>
        {crawlResult && <AuthenticatedCrawlResultView result={crawlResult} />}
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading">
          <div><h2>Auth-Required Endpoints</h2><p>Classification only. No bypass or live auth testing is performed.</p></div>
          <button className="secondary-button" type="button" disabled={!selected || loading} onClick={() => void runEndpointClassification()}>Classify Endpoints</button>
        </div>
        <div className="table-shell">
          <table>
            <thead><tr><th>Endpoint</th><th>Classification</th><th>Reason</th><th>Role</th><th>Source</th></tr></thead>
            <tbody>{classified.map((item, index) => (
              <tr key={`${item.url || item.normalised_url}-${index}`}><td>{String(item.normalised_url || item.url || item.path || '')}</td><td>{String(item.auth_required_classification || 'unknown')}</td><td>{String(item.auth_classification_reason || '')}</td><td>{String(item.role_label || selected?.role_label || '')}</td><td>{String(item.source || item.input_source || 'endpoint_results')}</td></tr>
            ))}</tbody>
          </table>
        </div>
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading"><h2>Role/Permission Notes</h2><p>Use safe labels and notes only. Do not store real usernames or credentials.</p></div>
        <div className="role-note-grid">
          <div><span>Role</span><strong>{selected?.role_label || 'Not set'}</strong></div>
          <div><span>Allowed actions</span><p>Defined manually by assessment owner.</p></div>
          <div><span>Disallowed actions</span><p>Delete, payment, transfer, and destructive admin actions should remain blocked unless explicitly authorised.</p></div>
          <div><span>Notes</span><p>{selected?.permission_notes || selected?.notes || 'No role notes supplied.'}</p></div>
        </div>
      </article>
    </section>
  )
}

function AuthenticatedCrawlResultView({ result }: { result: AuthenticatedCrawlResponse }) {
  const summary = result.authenticated_crawl_summary || {}
  const rows = result.authenticated_crawl_results || []
  const events = result.authenticated_boundary_events || []
  return (
    <div className="auth-crawl-results">
      <div className="auth-crawl-summary">
        <div><span>Pages crawled</span><strong>{String(summary.pages_crawled ?? 0)}</strong></div>
        <div><span>Endpoints</span><strong>{String(summary.endpoints_discovered ?? 0)}</strong></div>
        <div><span>Blocked paths</span><strong>{String(summary.blocked_by_boundary_count ?? 0)}</strong></div>
        <div><span>Skipped destructive</span><strong>{String(summary.skipped_destructive_count ?? 0)}</strong></div>
        <div><span>Session Expiry Indicator</span><strong>{String(summary.session_expiry_indicators_count ?? 0)}</strong></div>
        <div><span>Auth-required endpoints</span><strong>{String(summary.auth_required_endpoints_count ?? 0)}</strong></div>
      </div>
      <div className="table-shell">
        <table>
          <thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Auth Required</th><th>Session Expiry</th><th>Category</th></tr></thead>
          <tbody>{rows.map((row, index) => (
            <tr key={`${row.url}-${index}`}><td>{String(row.url || '')}</td><td>{String(row.status_code ?? '')}</td><td>{String(row.page_title || row.title || '')}</td><td>{String(row.auth_required_likely || false)}</td><td>{String(row.session_expiry_indicator || false)}</td><td>{String(row.endpoint_category || '')}</td></tr>
          ))}</tbody>
        </table>
      </div>
      <div className="table-shell">
        <table>
          <thead><tr><th>URL</th><th>Event</th><th>Reason</th><th>Action</th></tr></thead>
          <tbody>{events.map((event, index) => (
            <tr key={`${event.url}-${index}`}><td>{String(event.url || '')}</td><td>{String(event.event_type || '')}</td><td>{String(event.reason || '')}</td><td>{String(event.action_taken || '')}</td></tr>
          ))}</tbody>
        </table>
      </div>
      <div className="panel-message">Redacted Authenticated Evidence only. Raw cookies, bearer tokens, passwords, and Authorization headers are not displayed.</div>
    </div>
  )
}

function ProfileDetail({ profile }: { profile: SessionProfileSummary }) {
  return (
    <div className="auth-profile-detail">
      <div><span>Cookie names</span><strong>{(profile.cookie_names || []).join(', ') || 'None'}</strong></div>
      <div><span>Header names</span><strong>{(profile.header_names || []).join(', ') || 'None'}</strong></div>
      <div><span>Allowed hosts</span><strong>{(profile.allowed_hosts || []).join(', ') || 'None'}</strong></div>
      <div><span>Allowed paths</span><strong>{(profile.allowed_paths || []).join(', ') || 'None'}</strong></div>
      <div><span>Blocked paths</span><strong>{(profile.blocked_paths || []).join(', ') || 'None'}</strong></div>
      <div><span>Notes</span><strong>{profile.notes || 'None'}</strong></div>
    </div>
  )
}

function RedactionBadge({ status }: { status?: string }) {
  return <span className={`auth-redaction-badge auth-redaction-badge--${status || 'unknown'}`}>{status || 'unknown'}</span>
}

function demoClassifiedEndpoints(): Array<Record<string, unknown>> {
  return [
    { url: 'http://127.0.0.1:8000/dashboard', auth_required_classification: 'auth_required_likely', auth_classification_reason: 'Path suggests an Auth-Required Endpoint.', role_label: 'standard_user', source: 'demo' },
    { url: 'http://127.0.0.1:8000/login', auth_required_classification: 'public_likely', auth_classification_reason: 'Endpoint appears reachable from available metadata.', role_label: 'standard_user', source: 'demo' },
  ]
}

function demoCrawlResult(): AuthenticatedCrawlResponse {
  return {
    authenticated_crawl_summary: {
      enabled: true,
      pages_crawled: 2,
      endpoints_discovered: 2,
      blocked_by_boundary_count: 1,
      skipped_destructive_count: 1,
      session_expiry_indicators_count: 1,
      auth_required_endpoints_count: 1,
      redaction_applied: true,
    },
    authenticated_crawl_results: [
      { url: 'http://127.0.0.1:8000/dashboard', status_code: 200, page_title: 'Dashboard', auth_required_likely: true, session_expiry_indicator: false, endpoint_category: 'authenticated_likely' },
      { url: 'http://127.0.0.1:8000/account', status_code: 401, page_title: 'Login', auth_required_likely: true, session_expiry_indicator: true, endpoint_category: 'auth_required_likely' },
    ],
    authenticated_boundary_events: [
      { url: 'http://127.0.0.1:8000/logout', event_type: 'logout_path_skipped', reason: 'Path matches the default destructive path blocklist.', action_taken: 'skipped' },
    ],
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Authenticated Assessment request failed.'
}
