import { useMemo, useState } from 'react'
import { buildAccessTestReportTemplate, createAccessTest, observeAccessTest, retestAccessTest } from '../api/client'
import type { A01AccessObservation, A01AccessRetest, A01ManualTestPlan, AccessTestPlannerResponse, JobResultResponse } from '../types/api'
import { ErrorAlert } from './ErrorAlert'

interface Props {
  apiOnline: boolean
  demoMode?: boolean
  jobResult?: JobResultResponse | null
}

const demoPlans: A01ManualTestPlan[] = [{
  test_plan_id: 'demo-plan-001',
  title: 'Standard User Admin Function Review',
  test_type: 'vertical_access_control_review',
  affected_url: 'http://127.0.0.1:8000/admin/users',
  role_label: 'Standard User',
  role_id: 'standard_user',
  expected_permission: 'denied',
  expected_secure_behaviour: 'Only roles with explicit authorization can access this function.',
  validation_status: 'planned',
  manual_steps: ['Use a lower-privileged authorised test role.', 'Confirm admin/management function is denied.', 'Avoid state-changing actions.', 'Prefer GET/view-only checks where possible.'],
  safety_notes: ['Authorised Test Accounts Only.', 'Capture redacted evidence only.'],
  risk_if_failed: 'Potential Function-Level Authorization Review issue if roles without explicit authorization can use the function.',
  recommendation: 'Enforce server-side role and permission checks for the function.',
  evidence_checklist: {
    items: [
      { item_id: 'item-1', item: 'Authorisation scope confirmed.', status: 'completed', required: true, notes: 'Demo local scope.' },
      { item_id: 'item-2', item: 'Observed behaviour recorded.', status: 'pending', required: true, notes: '' },
      { item_id: 'item-3', item: 'No secrets included.', status: 'pending', required: true, notes: '' },
    ],
  },
}]

export function A01ManualTestPlannerView({ apiOnline, demoMode = false, jobResult }: Props) {
  const result = jobResult?.result as Record<string, unknown> | null | undefined
  const resultPlans = (result?.access_control_test_plans as A01ManualTestPlan[] | undefined) || []
  const [plans, setPlans] = useState<A01ManualTestPlan[]>(resultPlans.length ? resultPlans : demoPlans)
  const [selectedId, setSelectedId] = useState(plans[0]?.test_plan_id || '')
  const [observations, setObservations] = useState<A01AccessObservation[]>((result?.access_control_observations as A01AccessObservation[] | undefined) || [])
  const [retests, setRetests] = useState<A01AccessRetest[]>((result?.access_control_retests as A01AccessRetest[] | undefined) || [])
  const [observedResult, setObservedResult] = useState('denied_as_expected')
  const [statusCode, setStatusCode] = useState('403')
  const [observedSummary, setObservedSummary] = useState('Access denied for standard_user as expected')
  const [testerNotes, setTesterNotes] = useState('')
  const [retestStatus, setRetestStatus] = useState('passed')
  const [retestNotes, setRetestNotes] = useState('Access remains denied after remediation')
  const [reportTemplate, setReportTemplate] = useState<Record<string, unknown> | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const selected = useMemo(() => plans.find((plan) => plan.test_plan_id === selectedId) || plans[0], [plans, selectedId])
  const selectedObservation = observations.find((item) => item.test_plan_id === selected?.test_plan_id) || selected?.observed_behaviour as A01AccessObservation | undefined
  const selectedRetest = retests.find((item) => item.test_plan_id === selected?.test_plan_id)
  const summary = buildSummary(plans, observations, retests)

  async function createDemoPlan() {
    setLoading(true)
    setError(null)
    try {
      const response = demoMode || !apiOnline
        ? { access_control_test_plan: demoPlans[0] }
        : await createAccessTest({
          role: { role_id: 'standard_user', role_name: 'standard_user', role_label: 'Standard User', user_type: 'standard_user' },
          endpoint: { url: 'http://127.0.0.1:8000/admin/users', method: 'GET' },
          expected_permission: 'denied',
          test_type: 'vertical_access_control_review',
        })
      const plan = response.access_control_test_plan
      if (plan) {
        setPlans((current) => current.some((item) => item.test_plan_id === plan.test_plan_id) ? current : [plan, ...current])
        setSelectedId(plan.test_plan_id || '')
      }
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  async function saveObservation() {
    if (!selected?.test_plan_id) return
    setLoading(true)
    setError(null)
    try {
      const payload = { test_plan_id: selected.test_plan_id, observed_access_result: observedResult, observed_status_code: Number(statusCode) || undefined, observed_message_summary: observedSummary, evidence_summary: observedSummary, tester_notes: testerNotes }
      const response: AccessTestPlannerResponse = demoMode || !apiOnline
        ? { access_control_observation: { observation_id: `demo-observation-${Date.now()}`, ...payload, redaction_status: 'redacted' } }
        : await observeAccessTest(payload)
      if (response.access_control_observation) setObservations((current) => [response.access_control_observation as A01AccessObservation, ...current])
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  async function saveRetest() {
    if (!selected?.test_plan_id) return
    setLoading(true)
    setError(null)
    try {
      const payload = { test_plan_id: selected.test_plan_id, retest_status: retestStatus, retest_observed_result: retestStatus, retest_notes: retestNotes }
      const response = demoMode || !apiOnline
        ? { access_control_retest: { retest_id: `demo-retest-${Date.now()}`, ...payload } }
        : await retestAccessTest(payload)
      if (response.access_control_retest) setRetests((current) => [response.access_control_retest as A01AccessRetest, ...current])
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
        ? { a01_report_template: demoReportTemplate(selected, selectedObservation, selectedRetest) }
        : await buildAccessTestReportTemplate({ plan: selected, observation: selectedObservation || null, retest: selectedRetest || null })
      setReportTemplate(response.a01_report_template || null)
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="content-grid a01-manual-planner">
      <article className="panel panel--wide">
        <div className="panel-heading">
          <div><h2>A01 Manual Test Planner</h2><p>Access Control Manual Test Planner, Expected Behaviour, Observed Behaviour, Evidence Checklist, and Retest Workflow.</p></div>
          <button className="primary-button" type="button" disabled={loading} onClick={() => void createDemoPlan()}>Create Plan</button>
        </div>
        <div className="auth-safety-notice">Manual test plans are for authorised testing only. VulScan does not perform automatic access checks, account-to-account requests, or state-changing actions.</div>
        <ErrorAlert message={error} />
      </article>

      <article className="panel panel--wide">
        <div className="planner-summary">
          <Metric label="Planned" value={summary.planned} />
          <Metric label="In Progress" value={summary.inProgress} />
          <Metric label="Verified Secure" value={summary.secure} />
          <Metric label="Verified Issue" value={summary.issue} />
          <Metric label="Retest Passed" value={summary.retestPassed} />
          <Metric label="Retest Failed" value={summary.retestFailed} />
        </div>
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading"><h2>Test Plan Table</h2><p>Manual Validation Required workflow records.</p></div>
        <div className="table-shell"><table><thead><tr><th>Plan ID</th><th>Title</th><th>Role</th><th>Endpoint</th><th>Test Type</th><th>Expected</th><th>Status</th><th>Retest</th></tr></thead><tbody>
          {plans.map((plan) => <tr key={plan.test_plan_id} onClick={() => setSelectedId(plan.test_plan_id || '')}><td>{plan.test_plan_id}</td><td>{plan.title}</td><td>{plan.role_label}</td><td>{plan.affected_url}</td><td>{plan.test_type}</td><td>{plan.expected_permission}</td><td><StatusBadge status={plan.validation_status} /></td><td>{retests.find((item) => item.test_plan_id === plan.test_plan_id)?.retest_status || 'not_started'}</td></tr>)}
        </tbody></table></div>
      </article>

      {selected && <article className="panel panel--wide">
        <div className="panel-heading"><h2>Plan Detail</h2><p>Expected Behaviour, manual steps, and linked context.</p></div>
        <div className="manual-plan-card">
          <div><span>Expected Behaviour</span><p>{selected.expected_secure_behaviour}</p></div>
          <div><span>Risk If Failed</span><p>{selected.risk_if_failed}</p></div>
          <div><span>Recommendation</span><p>{selected.recommendation}</p></div>
          <div><span>Linked A01 Evidence</span><p>{selected.linked_a01_evidence_id || 'None'}</p></div>
          <div><span>Linked Role Matrix</span><p>{selected.linked_role_matrix_id || 'None'}</p></div>
          <div><span>Manual Steps</span><ul>{(selected.manual_steps || []).map((step) => <li key={step}>{step}</li>)}</ul></div>
          <div><span>Safety Notes</span><ul>{(selected.safety_notes || []).map((note) => <li key={note}>{note}</li>)}</ul></div>
        </div>
      </article>}

      {selected && <article className="panel panel--wide">
        <div className="panel-heading"><h2>Evidence Checklist</h2><p>Required evidence readiness items.</p></div>
        <div className="table-shell"><table><thead><tr><th>Item</th><th>Status</th><th>Required</th><th>Notes</th></tr></thead><tbody>
          {(((selected.evidence_checklist || {}).items as Array<Record<string, unknown>> | undefined) || []).map((item) => <tr key={String(item.item_id)}><td>{String(item.item)}</td><td>{String(item.status)}</td><td>{String(item.required)}</td><td>{String(item.notes || '')}</td></tr>)}
        </tbody></table></div>
      </article>}

      {selected && <article className="panel panel--wide">
        <div className="panel-heading"><h2>Expected vs Observed</h2><p>Record redacted manual observation only.</p></div>
        <div className="planner-form">
          <label><span>Observed Result</span><select value={observedResult} onChange={(event) => setObservedResult(event.target.value)}><option value="denied_as_expected">denied_as_expected</option><option value="allowed_as_expected">allowed_as_expected</option><option value="unexpectedly_allowed">unexpectedly_allowed</option><option value="unexpectedly_denied">unexpectedly_denied</option><option value="inconclusive">inconclusive</option><option value="not_tested">not_tested</option></select></label>
          <label><span>Status Code</span><input value={statusCode} onChange={(event) => setStatusCode(event.target.value)} /></label>
          <label><span>Redacted Summary</span><input value={observedSummary} onChange={(event) => setObservedSummary(event.target.value)} /></label>
          <label><span>Tester Notes</span><input value={testerNotes} onChange={(event) => setTesterNotes(event.target.value)} /></label>
          <button className="secondary-button" type="button" disabled={loading} onClick={() => void saveObservation()}>Save Observation</button>
        </div>
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
        <div className="panel-heading"><h2>Report Template</h2><p>Report-ready A01 text uses candidate wording unless manual observation confirms an issue.</p></div>
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

function buildSummary(plans: A01ManualTestPlan[], observations: A01AccessObservation[], retests: A01AccessRetest[]) {
  return {
    planned: plans.filter((plan) => (plan.validation_status || 'planned') === 'planned').length,
    inProgress: plans.filter((plan) => plan.validation_status === 'in_progress').length,
    secure: observations.filter((item) => ['denied_as_expected', 'allowed_as_expected'].includes(item.observed_access_result || '')).length,
    issue: observations.filter((item) => ['unexpectedly_allowed', 'unexpectedly_denied'].includes(item.observed_access_result || '')).length,
    retestPassed: retests.filter((item) => item.retest_status === 'passed').length,
    retestFailed: retests.filter((item) => item.retest_status === 'failed').length,
  }
}

function demoReportTemplate(plan: A01ManualTestPlan, observation?: A01AccessObservation, retest?: A01AccessRetest) {
  const issue = ['unexpectedly_allowed', 'unexpectedly_denied'].includes(observation?.observed_access_result || '')
  return {
    Title: `${issue ? 'Manually Verified A01 Issue' : 'A01 Manual Validation Plan'}: ${plan.title}`,
    Summary: issue ? 'Observed Behaviour differs from Expected Behaviour.' : 'Candidate plan awaiting manual validation.',
    'Affected Endpoint': plan.affected_url,
    'Affected Role': plan.role_label,
    'Expected Behaviour': plan.expected_secure_behaviour,
    'Observed Behaviour': observation?.observed_message_summary || 'Manual validation has not confirmed an issue.',
    Recommendation: plan.recommendation,
    'Retest Notes': retest?.retest_notes || '',
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Request failed.'
}
