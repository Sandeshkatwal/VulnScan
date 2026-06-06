import type { A01AccessControlEvidenceItem } from '../types/api'

export function A01EvidenceTemplatePanel({ selected }: { selected?: A01AccessControlEvidenceItem }) {
  if (!selected?.evidence_template) return <div className="panel-message">No A01 evidence template is available for this candidate.</div>
  const template = selected.evidence_template
  return (
    <div className="a01-template">
      <p><strong>Candidate title:</strong> {template.candidate_title}</p>
      <p><strong>Affected endpoint:</strong> {template.affected_endpoint}</p>
      <p><strong>Parameter/object identifier:</strong> {template.parameter_or_object_identifier || 'none'}</p>
      <p><strong>Candidate type:</strong> {template.candidate_type}</p>
      <p><strong>Why it may matter:</strong> {template.why_it_may_matter}</p>
      <p><strong>Risk if confirmed:</strong> {template.risk_if_confirmed}</p>
      <p><strong>Recommendation:</strong> {template.recommendation}</p>
    </div>
  )
}
