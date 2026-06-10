import { useMemo, useState } from 'react'
import { buildBusinessLogicReportTemplate, createBusinessLogicPlan, observeBusinessLogic, retestBusinessLogic } from '../api/client'
import type { BusinessLogicObservation, BusinessLogicRetest, BusinessLogicReviewPlan, BusinessLogicWorkflowCandidate, JobResultResponse } from '../types/api'
import { ErrorAlert } from './ErrorAlert'

interface Props {
  apiOnline: boolean
  demoMode?: boolean
  jobResult?: JobResultResponse | null
}

const demoCandidate: BusinessLogicWorkflowCandidate = {
  workflow_candidate_id: 'demo-candidate-001',
  workflow_type: 'checkout_payment',
  affected_url: 'http://127.0.0.1:8000/checkout',
  workflow_sensitivity: 'critical',
  candidate_score: 85,
  related_roles: ['standard_user'],
  related_parameters: ['order_id'],
  related_owasp_categories: ['A01', 'A06', 'A08'],
}

const demoPlan: BusinessLogicReviewPlan = {
  review_plan_id: 'demo-workflow-001',
  title: 'Business Logic Review: Checkout Payment',
  workflow_type: 'checkout_payment',
  affected_urls: ['http://127.0.0.1:8000/checkout'],
  related_roles: ['standard_user'],
  related_parameters: ['order_id'],
  related_owasp_categories: ['A01', 'A06', 'A08'],
  expected_business_rule: 'Checkout must enforce allowed roles, states, order totals, and payment state server-side.',
  expected_secure_behaviour: 'Payment, checkout, order, and price-sensitive operations must enforce server-side validation, authorization, and anti-tampering controls.',
  validation_status: 'planned',
  retest_status: 'not_started',
  risk_if_failed: 'Potential financial, pricing, entitlement, or transaction integrity impact if manually confirmed.',
  recommendation: 'Enforce Business Rule Review controls server-side and document allowed state transitions, roles, limits, and audit events.',
  manual_steps: ['Confirm scope and Authorised Test Data Only.', 'Document the Expected Business Rule before manual review.', 'Map allowed and disallowed State Transition Review paths.', 'Complete the Abuse Case Checklist.', 'Record Expected Behaviour and Observed Behaviour with redacted evidence.'],
  safety_notes: ['Manual Validation Required.', 'Authorised Test Data Only.', 'No Automatic Workflow Execution.'],
  state_transition_map: {
    transitions: [
      { transition_id: 't1', from_state: 'cart', to_state: 'checkout', action: 'start_checkout', allowed_roles: ['standard_user'], disallowed_roles: [], expected_control: 'Server-side state control.' },
      { transition_id: 't2', from_state: 'checkout', to_state: 'paid', action: 'confirm_payment', allowed_roles: ['standard_user'], disallowed_roles: [], expected_control: 'Server-side payment state control.' },
    ],
  },
  abuse_cases: {
    items: [
      { item_id: 'a1', item: 'Can workflow steps be skipped?', status: 'pending', required: true, notes: '' },
      { item_id: 'a2', item: 'price tampering review', status: 'pending', required: true, notes: '' },
      { item_id: 'a3', item: 'Is audit logging present?', status: 'pending', required: true, notes: '' },
    ],
  },
}

export function BusinessLogicReviewView({ apiOnline, demoMode = false, jobResult }: Props) {
  const result = jobResult?.result as Record<string, unknown> | null | undefined
  const resultCandidates = (result?.business_logic_workflow_candidates as BusinessLogicWorkflowCandidate[] | undefined) || []
  const resultPlans = (result?.business_logic_review_plans as BusinessLogicReviewPlan[] | undefined) || []
  const [candidates] = useState<BusinessLogicWorkflowCandidate[]>(resultCandidates.length ? resultCandidates : [demoCandidate])
  const [plans, setPlans] = useState<BusinessLogicReviewPlan[]>(resultPlans.length ? resultPlans : [demoPlan])
  const [selectedId, setSelectedId] = useState(plans[0]?.review_plan_id || '')
  const [observations, setObservations] = useState<BusinessLogicObservation[]>((result?.business_logic_observations as BusinessLogicObservation[] | undefined) || [])
  const [retests, setRetests] = useState<BusinessLogicRetest[]>((result?.business_logic_retests as BusinessLogicRetest[] | undefined) || [])
  const [observedResult, setObservedResult] = useState('behaved_as_expected')
  const [observedSummary, setObservedSummary] = useState('Workflow behaved as expected using approved test data')
  const [testerNotes, setTesterNotes] = useState('')
  const [retestStatus, setRetestStatus] = useState('passed')
  const [retestNotes, setRetestNotes] = useState('Workflow control still enforced after remediation')
  const [reportTemplate, setReportTemplate] = useState<Record<string, unknown> | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const selected = useMemo(() => plans.find((plan) => plan.review_plan_id === selectedId) || plans[0], [plans, selectedId])
  const selectedObservation = observations.find((item) => item.review_plan_id === selected?.review_plan_id) || selected?.observed_behaviour as BusinessLogicObservation | undefined
  const selectedRetest = retests.find((item) => item.review_plan_id === selected?.review_plan_id)
  const summary = buildSummary(candidates, observations, retests)

  async function createDemoPlan() {
    setLoading(true)
    setError(null)
    try {
      const response = demoMode || !apiOnline
        ? { business_logic_review_plan: demoPlan }
        : await createBusinessLogicPlan({ workflow: 'checkout_payment', endpoint: 'http://127.0.0.1:8000/checkout', role: 'standard_user' })
      if (response.business_logic_review_plan) {
        setPlans((current) => current.some((item) => item.review_plan_id === response.business_logic_review_plan?.review_plan_id) ? current : [response.business_logic_review_plan as BusinessLogicReviewPlan, ...current])
        setSelectedId(response.business_logic_review_plan.review_plan_id || '')
      }
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  async function saveObservation() {
    if (!selected?.review_plan_id) return
    setLoading(true)
    setError(null)
    try {
      const payload = { review_plan_id: selected.review_plan_id, observed_result: observedResult, observed_message_summary: observedSummary, evidence_summary: observedSummary, tester_notes: testerNotes }
      const response = demoMode || !apiOnline ? { business_logic_observation: { observation_id: `demo-observation-${Date.now()}`, ...payload, redaction_status: 'redacted' } } : await observeBusinessLogic(payload)
      if (response.business_logic_observation) setObservations((current) => [response.business_logic_observation as BusinessLogicObservation, ...current])
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  async function saveRetest() {
    if (!selected?.review_plan_id) return
    setLoading(true)
    setError(null)
    try {
      const payload = { review_plan_id: selected.review_plan_id, retest_status: retestStatus, retest_observed_result: retestStatus, retest_notes: retestNotes }
      const response = demoMode || !apiOnline ? { business_logic_retest: { retest_id: `demo-retest-${Date.now()}`, ...payload } } : await retestBusinessLogic(payload)
      if (response.business_logic_retest) setRetests((current) => [response.business_logic_retest as BusinessLogicRetest, ...current])
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
      const response = demoMode || !apiOnline ? { business_logic_report_template: demoReportTemplate(selected, selectedObservation, selectedRetest) } : await buildBusinessLogicReportTemplate({ plan: selected, observation: selectedObservation || null, retest: selectedRetest || null })
      setReportTemplate(response.business_logic_report_template || null)
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="content-grid business-logic-review">
      <article className="panel panel--wide">
        <div className="panel-heading">
          <div><h2>Business Logic Review</h2><p>Workflow Review Plans, State Transition Review, Abuse Case Checklist, Expected Behaviour, Observed Behaviour, and Retest Workflow.</p></div>
          <button className="primary-button" type="button" disabled={loading} onClick={() => void createDemoPlan()}>Create Plan</button>
        </div>
        <div className="auth-safety-notice">Business logic review plans are manual workflows only. VulScan does not execute checkout, payment, approval, coupon, rate-limit, or state-changing workflows automatically.</div>
        <ErrorAlert message={error} />
      </article>

      <article className="panel panel--wide"><div className="planner-summary">
        <Metric label="Critical" value={summary.critical} /><Metric label="High" value={summary.high} /><Metric label="Medium" value={summary.medium} /><Metric label="Financial" value={summary.financial} /><Metric label="Verified Issue" value={summary.issue} /><Metric label="Retest Passed" value={summary.retestPassed} />
      </div></article>

      <article className="panel panel--wide">
        <div className="panel-heading"><h2>Workflow Plan Table</h2><p>Manual Validation Required workflow records.</p></div>
        <div className="table-shell"><table><thead><tr><th>Plan ID</th><th>Workflow Type</th><th>Endpoint</th><th>Role</th><th>Sensitivity</th><th>Status</th><th>Retest</th></tr></thead><tbody>
          {plans.map((plan) => <tr key={plan.review_plan_id} onClick={() => setSelectedId(plan.review_plan_id || '')}><td>{plan.review_plan_id}</td><td>{plan.workflow_type}</td><td>{(plan.affected_urls || []).join(', ')}</td><td>{(plan.related_roles || []).join(', ')}</td><td><RiskBadge workflowType={plan.workflow_type} /></td><td><StatusBadge status={plan.validation_status} /></td><td>{plan.retest_status || 'not_started'}</td></tr>)}
        </tbody></table></div>
      </article>

      {selected && <article className="panel panel--wide">
        <div className="panel-heading"><h2>Plan Detail</h2><p>Expected business rule, expected secure behaviour, manual steps, and linked plan context.</p></div>
        <div className="manual-plan-card">
          <div><span>Expected Business Rule</span><p>{selected.expected_business_rule}</p></div>
          <div><span>Expected Secure Behaviour</span><p>{selected.expected_secure_behaviour}</p></div>
          <div><span>Risk If Failed</span><p>{selected.risk_if_failed}</p></div>
          <div><span>Recommendation</span><p>{selected.recommendation}</p></div>
          <div><span>Linked Replay Plans</span><p>{(selected.linked_replay_plans || []).join(', ') || 'None'}</p></div>
          <div><span>Linked Access Plans</span><p>{(selected.linked_access_test_plans || []).join(', ') || 'None'}</p></div>
          <div><span>Manual Steps</span><ul>{(selected.manual_steps || []).map((step) => <li key={step}>{step}</li>)}</ul></div>
          <div><span>Safety Notes</span><ul>{(selected.safety_notes || []).map((note) => <li key={note}>{note}</li>)}</ul></div>
        </div>
      </article>}

      {selected && <article className="panel panel--wide">
        <div className="panel-heading"><h2>State Transition Map</h2><p>Expected transitions and controls.</p></div>
        <div className="table-shell"><table><thead><tr><th>From</th><th>To</th><th>Action</th><th>Allowed Roles</th><th>Expected Control</th></tr></thead><tbody>
          {(((selected.state_transition_map || {}).transitions as Array<Record<string, unknown>> | undefined) || []).map((item) => <tr key={String(item.transition_id)}><td>{String(item.from_state)}</td><td>{String(item.to_state)}</td><td>{String(item.action)}</td><td>{Array.isArray(item.allowed_roles) ? item.allowed_roles.join(', ') : ''}</td><td>{String(item.expected_control || '')}</td></tr>)}
        </tbody></table></div>
      </article>}

      {selected && <article className="panel panel--wide">
        <div className="panel-heading"><h2>Abuse Case Checklist</h2><p>Checklist status and notes.</p></div>
        <div className="table-shell"><table><thead><tr><th>Item</th><th>Status</th><th>Required</th><th>Notes</th></tr></thead><tbody>
          {(((selected.abuse_cases || {}).items as Array<Record<string, unknown>> | undefined) || []).map((item) => <tr key={String(item.item_id)}><td>{String(item.item)}</td><td>{String(item.status)}</td><td>{String(item.required)}</td><td>{String(item.notes || '')}</td></tr>)}
        </tbody></table></div>
      </article>}

      {selected && <article className="panel panel--wide">
        <div className="panel-heading"><h2>Expected vs Observed</h2><p>Record redacted manual observation only.</p></div>
        <div className="planner-form">
          <label><span>Observed Result</span><select value={observedResult} onChange={(event) => setObservedResult(event.target.value)}><option value="behaved_as_expected">behaved_as_expected</option><option value="unexpected_success">unexpected_success</option><option value="unexpected_denial">unexpected_denial</option><option value="control_missing">control_missing</option><option value="inconclusive">inconclusive</option><option value="not_tested">not_tested</option></select></label>
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
        <div className="panel-heading"><h2>Report Template</h2><p>Report-ready text uses candidate wording unless manual observation confirms an issue.</p></div>
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

function RiskBadge({ workflowType }: { workflowType?: string }) {
  const critical = ['checkout_payment', 'refund_transfer'].includes(workflowType || '')
  return <span className={`a01-status-badge ${critical ? 'a01-status-badge--manually-verified-issue' : 'a01-status-badge--planned'}`}>{critical ? 'critical' : 'manual'}</span>
}

function buildSummary(candidates: BusinessLogicWorkflowCandidate[], observations: BusinessLogicObservation[], retests: BusinessLogicRetest[]) {
  return {
    critical: candidates.filter((item) => item.workflow_sensitivity === 'critical').length,
    high: candidates.filter((item) => item.workflow_sensitivity === 'high').length,
    medium: candidates.filter((item) => item.workflow_sensitivity === 'medium').length,
    financial: candidates.filter((item) => ['checkout_payment', 'refund_transfer', 'subscription_plan', 'coupon_discount'].includes(item.workflow_type || '')).length,
    issue: observations.filter((item) => ['unexpected_success', 'control_missing'].includes(item.observed_result || '')).length,
    retestPassed: retests.filter((item) => item.retest_status === 'passed').length,
  }
}

function demoReportTemplate(plan: BusinessLogicReviewPlan, observation?: BusinessLogicObservation, retest?: BusinessLogicRetest) {
  const issue = ['unexpected_success', 'control_missing'].includes(observation?.observed_result || '')
  return {
    Title: `${issue ? 'Manually Verified Business Logic Issue' : 'Business Logic Review Plan'}: ${plan.title}`,
    Summary: issue ? 'Observed Behaviour differs from the Expected Business Rule.' : 'Candidate Business Logic Review plan awaiting manual validation.',
    'Workflow Type': plan.workflow_type,
    'Affected Endpoint(s)': plan.affected_urls || [],
    'Role/Context': (plan.related_roles || []).join(', '),
    'Expected Business Rule': plan.expected_business_rule,
    'Expected Secure Behaviour': plan.expected_secure_behaviour,
    'Observed Behaviour': observation?.observed_message_summary || 'Manual validation has not confirmed an issue.',
    'Retest Notes': retest?.retest_notes || '',
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Request failed.'
}
