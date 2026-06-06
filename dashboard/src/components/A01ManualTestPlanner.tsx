import type { A01AccessControlEvidenceItem } from '../types/api'

export function A01ManualTestPlanner({ selected }: { selected?: A01AccessControlEvidenceItem }) {
  if (!selected) return <div className="panel-message">Select a high-interest candidate from the report data to build a manual validation plan.</div>
  const template = selected.evidence_template || {}
  return (
    <div className="a01-plan">
      <div>
        <span className="label">Selected candidate</span>
        <strong>{selected.title || 'A01 candidate'}</strong>
      </div>
      <div>
        <span className="label">Plan type</span>
        <strong>{selected.manual_test_plan_id || 'horizontal_access_control_review'}</strong>
      </div>
      <ul>
        {(selected.recommended_manual_steps || template.safe_manual_validation_steps || []).map((step) => <li key={step}>{step}</li>)}
      </ul>
      <p><strong>Expected secure behaviour:</strong> {template.expected_secure_behaviour || 'Server-side access-control enforcement blocks unauthorised object, tenant, or function access.'}</p>
      <p><strong>Evidence needed:</strong> {template.evidence_needed_for_confirmation || 'Redacted authorised-test-account evidence. Candidate requiring manual validation.'}</p>
    </div>
  )
}
