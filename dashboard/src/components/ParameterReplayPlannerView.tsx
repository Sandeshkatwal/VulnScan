import { useMemo, useState } from 'react'
import { buildReplayPlanReportTemplate, createReplayPlan, observeReplayPlan, retestReplayPlan } from '../api/client'
import type { JobResultResponse, ParameterReplayObservation, ParameterReplayPlan, ParameterReplayRetest, RedactedRequestTemplate } from '../types/api'
import { ErrorAlert } from './ErrorAlert'

interface Props {
  apiOnline: boolean
  demoMode?: boolean
  jobResult?: JobResultResponse | null
}

const demoPlan: ParameterReplayPlan = {
  replay_plan_id: 'demo-replay-001',
  title: 'Object Ownership Review: user_id',
  affected_url: 'http://127.0.0.1:8000/users/123?user_id=123',
  method: 'GET',
  parameter_name: 'user_id',
  replay_intent: 'object_ownership_review',
  role_label: 'standard_user',
  related_owasp_categories: ['A01'],
  validation_status: 'planned',
  expected_secure_behaviour: 'Only authorised owners or explicitly permitted users can access the referenced object.',
  safe_request_template_id: 'demo-template-001',
  manual_steps: ['Use authorised test accounts only.', 'Confirm original object belongs to approved test account.', 'Record expected vs observed behaviour.', 'Redact identifiers in evidence.'],
  safety_notes: ['No Automatic Replay.', 'Authorised Test Accounts Only.', 'Redacted Auth Context only.'],
  evidence_checklist: {
    items: [
      { item_id: 'item-1', item: 'Authorisation scope confirmed.', status: 'pending', required: true, notes: '' },
      { item_id: 'item-2', item: 'Request template redacted.', status: 'pending', required: true, notes: '' },
      { item_id: 'item-3', item: 'No secrets included.', status: 'pending', required: true, notes: '' },
    ],
  },
}

const demoTemplate: RedactedRequestTemplate = {
  template_id: 'demo-template-001',
  method: 'GET',
  url_template: 'http://127.0.0.1:8000/users/{id}?user_id={ORIGINAL_VALUE_REDACTED}',
  headers_redacted: { Authorization: '{ORIGINAL_VALUE_REDACTED}' },
  cookies_redacted: ['sessionid'],
  query_parameters: { user_id: ['{ORIGINAL_VALUE_REDACTED}', '{TEST_VALUE_APPROVED_MANUAL_ONLY}'] },
  path_parameters: { id: '{ORIGINAL_VALUE_REDACTED}' },
  state_changing: false,
  destructive: false,
  blocked_by_default: false,
  warnings: ['No Automatic Replay.', 'Authorised Test Accounts Only.'],
}

export function ParameterReplayPlannerView({ apiOnline, demoMode = false, jobResult }: Props) {
  const result = jobResult?.result as Record<string, unknown> | null | undefined
  const resultPlans = (result?.parameter_replay_plans as ParameterReplayPlan[] | undefined) || []
  const resultTemplates = (result?.redacted_request_templates as RedactedRequestTemplate[] | undefined) || []
  const [plans, setPlans] = useState<ParameterReplayPlan[]>(resultPlans.length ? resultPlans : [demoPlan])
  const [templates, setTemplates] = useState<RedactedRequestTemplate[]>(resultTemplates.length ? resultTemplates : [demoTemplate])
  const [observations, setObservations] = useState<ParameterReplayObservation[]>((result?.parameter_replay_observations as ParameterReplayObservation[] | undefined) || [])
  const [retests, setRetests] = useState<ParameterReplayRetest[]>((result?.parameter_replay_retests as ParameterReplayRetest[] | undefined) || [])
  const [selectedId, setSelectedId] = useState(plans[0]?.replay_plan_id || '')
  const [observedResult, setObservedResult] = useState('denied_as_expected')
  const [statusCode, setStatusCode] = useState('403')
  const [observedSummary, setObservedSummary] = useState('Access denied for standard_user as expected')
  const [testerNotes, setTesterNotes] = useState('')
  const [retestStatus, setRetestStatus] = useState('passed')
  const [retestNotes, setRetestNotes] = useState('Parameter access remains denied after remediation')
  const [reportTemplate, setReportTemplate] = useState<Record<string, unknown> | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const selected = useMemo(() => plans.find((plan) => plan.replay_plan_id === selectedId) || plans[0], [plans, selectedId])
  const selectedTemplate = templates.find((template) => template.template_id === selected?.safe_request_template_id) || templates[0]
  const selectedObservation = observations.find((item) => item.replay_plan_id === selected?.replay_plan_id) || selected?.observed_behaviour as ParameterReplayObservation | undefined
  const selectedRetest = retests.find((item) => item.replay_plan_id === selected?.replay_plan_id)
  const summary = buildSummary(plans, observations, retests)

  async function createDemoReplayPlan() {
    setLoading(true)
    setError(null)
    try {
      const response = demoMode || !apiOnline
        ? { parameter_replay_plan: demoPlan, redacted_request_template: demoTemplate }
        : await createReplayPlan({ endpoint: 'http://127.0.0.1:8000/users/123?user_id=123', parameter: 'user_id', intent: 'object_ownership_review', role: 'standard_user' })
      if (response.parameter_replay_plan) {
        setPlans((current) => current.some((item) => item.replay_plan_id === response.parameter_replay_plan?.replay_plan_id) ? current : [response.parameter_replay_plan as ParameterReplayPlan, ...current])
        setSelectedId(response.parameter_replay_plan.replay_plan_id || '')
      }
      if (response.redacted_request_template) setTemplates((current) => [response.redacted_request_template as RedactedRequestTemplate, ...current])
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  async function saveObservation() {
    if (!selected?.replay_plan_id) return
    setLoading(true)
    setError(null)
    try {
      const payload = { replay_plan_id: selected.replay_plan_id, observed_access_result: observedResult, observed_status_code: Number(statusCode) || undefined, observed_message_summary: observedSummary, evidence_summary: observedSummary, tester_notes: testerNotes }
      const response = demoMode || !apiOnline
        ? { parameter_replay_observation: { observation_id: `demo-observation-${Date.now()}`, ...payload, redaction_status: 'redacted' } }
        : await observeReplayPlan(payload)
      if (response.parameter_replay_observation) setObservations((current) => [response.parameter_replay_observation as ParameterReplayObservation, ...current])
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  async function saveRetest() {
    if (!selected?.replay_plan_id) return
    setLoading(true)
    setError(null)
    try {
      const payload = { replay_plan_id: selected.replay_plan_id, retest_status: retestStatus, retest_observed_result: retestStatus, retest_notes: retestNotes }
      const response = demoMode || !apiOnline
        ? { parameter_replay_retest: { retest_id: `demo-retest-${Date.now()}`, ...payload } }
        : await retestReplayPlan(payload)
      if (response.parameter_replay_retest) setRetests((current) => [response.parameter_replay_retest as ParameterReplayRetest, ...current])
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  async function generateTemplate() {
    if (!selected) return
    setLoading(true)
    setError(null)
    try {
      const response = demoMode || !apiOnline
        ? { parameter_replay_report_template: demoReportTemplate(selected, selectedObservation, selectedRetest) }
        : await buildReplayPlanReportTemplate({ plan: selected, observation: selectedObservation || null, retest: selectedRetest || null })
      setReportTemplate(response.parameter_replay_report_template || null)
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="content-grid parameter-replay-planner">
      <article className="panel panel--wide">
        <div className="panel-heading">
          <div><h2>Parameter Replay Planner</h2><p>Replay Plans, Redacted Request Templates, Parameter Review Plans, and Retest Workflow records.</p></div>
          <button className="primary-button" type="button" disabled={loading} onClick={() => void createDemoReplayPlan()}>Create Plan</button>
        </div>
        <div className="auth-safety-notice">Replay plans are manual templates only. VulScan does not replay requests, mutate parameters, send payloads, or perform auth bypass automatically.</div>
        <ErrorAlert message={error} />
      </article>

      <article className="panel panel--wide"><div className="planner-summary">
        <Metric label="Planned" value={summary.planned} /><Metric label="In Progress" value={summary.inProgress} /><Metric label="Verified Secure" value={summary.secure} /><Metric label="Verified Issue" value={summary.issue} /><Metric label="Retest Passed" value={summary.retestPassed} /><Metric label="Retest Failed" value={summary.retestFailed} />
      </div></article>

      <article className="panel panel--wide">
        <div className="panel-heading"><h2>Replay Plan Table</h2><p>Manual Validation Required workflow records.</p></div>
        <div className="table-shell"><table><thead><tr><th>Plan ID</th><th>Endpoint</th><th>Parameter</th><th>Intent</th><th>Role</th><th>OWASP</th><th>Status</th></tr></thead><tbody>
          {plans.map((plan) => <tr key={plan.replay_plan_id} onClick={() => setSelectedId(plan.replay_plan_id || '')}><td>{plan.replay_plan_id}</td><td>{plan.affected_url}</td><td>{plan.parameter_name}</td><td>{plan.replay_intent}</td><td>{plan.role_label}</td><td>{(plan.related_owasp_categories || []).join(', ')}</td><td><StatusBadge status={plan.validation_status} /></td></tr>)}
        </tbody></table></div>
      </article>

      {selectedTemplate && <article className="panel panel--wide">
        <div className="panel-heading"><h2>Redacted Request Template</h2><p>Header names, cookie names, placeholders, and safety flags only.</p></div>
        <div className="manual-plan-card">
          <div><span>Method</span><p>{selectedTemplate.method}</p></div>
          <div><span>URL Template</span><p>{selectedTemplate.url_template}</p></div>
          <div><span>Header Names Only</span><p>{Object.keys(selectedTemplate.headers_redacted || {}).join(', ') || 'None'}</p></div>
          <div><span>Cookie Names Only</span><p>{(selectedTemplate.cookies_redacted || []).join(', ') || 'None'}</p></div>
          <div><span>Parameter Placeholders</span><p>{Object.keys(selectedTemplate.query_parameters || {}).join(', ') || Object.keys(selectedTemplate.path_parameters || {}).join(', ') || 'None'}</p></div>
          <div><span>Flags</span><p>state-changing={String(selectedTemplate.state_changing)} destructive={String(selectedTemplate.destructive)} blocked={String(selectedTemplate.blocked_by_default)}</p></div>
          <div><span>Warnings</span><ul>{(selectedTemplate.warnings || []).map((warning) => <li key={warning}>{warning}</li>)}</ul></div>
        </div>
      </article>}

      {selected && <article className="panel panel--wide">
        <div className="panel-heading"><h2>Expected vs Observed</h2><p>Record redacted manual observation only.</p></div>
        <div className="planner-form">
          <label><span>Observed Result</span><select value={observedResult} onChange={(event) => setObservedResult(event.target.value)}><option value="denied_as_expected">denied_as_expected</option><option value="allowed_as_expected">allowed_as_expected</option><option value="unexpectedly_allowed">unexpectedly_allowed</option><option value="unexpectedly_denied">unexpectedly_denied</option><option value="reflected_as_expected">reflected_as_expected</option><option value="reflected_with_context_risk">reflected_with_context_risk</option><option value="inconclusive">inconclusive</option><option value="not_tested">not_tested</option></select></label>
          <label><span>Status Code</span><input value={statusCode} onChange={(event) => setStatusCode(event.target.value)} /></label>
          <label><span>Redacted Summary</span><input value={observedSummary} onChange={(event) => setObservedSummary(event.target.value)} /></label>
          <label><span>Tester Notes</span><input value={testerNotes} onChange={(event) => setTesterNotes(event.target.value)} /></label>
          <button className="secondary-button" type="button" disabled={loading} onClick={() => void saveObservation()}>Save Observation</button>
        </div>
      </article>}

      {selected && <article className="panel panel--wide">
        <div className="panel-heading"><h2>Evidence Checklist</h2><p>Required items for redacted manual validation evidence.</p></div>
        <div className="table-shell"><table><thead><tr><th>Item</th><th>Status</th><th>Required</th><th>Notes</th></tr></thead><tbody>
          {(((selected.evidence_checklist || {}).items as Array<Record<string, unknown>> | undefined) || []).map((item) => <tr key={String(item.item_id)}><td>{String(item.item)}</td><td>{String(item.status)}</td><td>{String(item.required)}</td><td>{String(item.notes || '')}</td></tr>)}
        </tbody></table></div>
      </article>}

      {selected && <article className="panel panel--wide">
        <div className="panel-heading"><h2>Retest Workflow</h2><p>Record remediation summary and Retest Workflow status.</p></div>
        <div className="planner-form">
          <label><span>Retest Status</span><select value={retestStatus} onChange={(event) => setRetestStatus(event.target.value)}><option value="not_started">not_started</option><option value="scheduled">scheduled</option><option value="in_progress">in_progress</option><option value="passed">passed</option><option value="failed">failed</option><option value="blocked">blocked</option><option value="not_applicable">not_applicable</option></select></label>
          <label><span>Retest Notes</span><input value={retestNotes} onChange={(event) => setRetestNotes(event.target.value)} /></label>
          <button className="secondary-button" type="button" disabled={loading} onClick={() => void saveRetest()}>Save Retest</button>
        </div>
      </article>}

      {selected && <article className="panel panel--wide">
        <div className="panel-heading"><h2>Report Template</h2><p>Candidate wording is used unless manual observation confirms an issue.</p></div>
        <button className="secondary-button" type="button" disabled={loading} onClick={() => void generateTemplate()}>Generate Template</button>
        {reportTemplate && <pre className="report-template-preview">{Object.entries(reportTemplate).map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join('; ') : String(value)}`).join('\n\n')}</pre>}
      </article>}
    </section>
  )
}

function Metric({ label, value }: { label: string; value: number }) {
  return <div><span>{label}</span><strong>{value}</strong></div>
}

function StatusBadge({ status }: { status?: string }) {
  return <span className={`a01-status-badge a01-status-badge--${String(status || 'planned').replace(/_/g, '-')}`}>{status || 'planned'}</span>
}

function buildSummary(plans: ParameterReplayPlan[], observations: ParameterReplayObservation[], retests: ParameterReplayRetest[]) {
  return {
    planned: plans.filter((plan) => (plan.validation_status || 'planned') === 'planned').length,
    inProgress: plans.filter((plan) => plan.validation_status === 'in_progress').length,
    secure: observations.filter((item) => ['denied_as_expected', 'allowed_as_expected', 'reflected_as_expected'].includes(item.observed_access_result || '')).length,
    issue: observations.filter((item) => ['unexpectedly_allowed', 'unexpectedly_denied', 'reflected_with_context_risk'].includes(item.observed_access_result || '')).length,
    retestPassed: retests.filter((item) => item.retest_status === 'passed').length,
    retestFailed: retests.filter((item) => item.retest_status === 'failed').length,
  }
}

function demoReportTemplate(plan: ParameterReplayPlan, observation?: ParameterReplayObservation, retest?: ParameterReplayRetest) {
  const issue = ['unexpectedly_allowed', 'reflected_with_context_risk'].includes(observation?.observed_access_result || '')
  return {
    Title: `${issue ? 'Manually Verified Parameter Replay Issue' : 'Replay Plan'}: ${plan.title}`,
    Summary: issue ? 'Observed Behaviour differs from Expected Behaviour.' : 'Candidate Replay Plan awaiting manual validation.',
    'Affected Endpoint': plan.affected_url,
    Parameter: plan.parameter_name,
    'Role/Context': plan.role_label,
    'Expected Behaviour': plan.expected_secure_behaviour,
    'Observed Behaviour': observation?.observed_message_summary || 'Manual validation has not confirmed an issue.',
    'Retest Notes': retest?.retest_notes || '',
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Request failed.'
}
