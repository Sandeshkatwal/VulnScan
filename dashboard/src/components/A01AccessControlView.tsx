import type { A01AccessControlEvidenceItem, A01AccessControlSummary } from '../types/api'
import { A01AdminSurfaceTable } from './A01AdminSurfaceTable'
import { A01EvidenceTemplatePanel } from './A01EvidenceTemplatePanel'
import { A01ManualTestPlanner } from './A01ManualTestPlanner'
import { A01ObjectIdCandidateTable } from './A01ObjectIdCandidateTable'
import { A01RecommendationPanel } from './A01RecommendationPanel'
import { A01SummaryCards } from './A01SummaryCards'
import { A01TenantBoundaryPanel } from './A01TenantBoundaryPanel'

export function A01AccessControlView({ summary, evidence = [] }: { summary?: A01AccessControlSummary; evidence?: A01AccessControlEvidenceItem[] }) {
  if (!summary?.enabled) {
    return (
      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>A01 Broken Access Control</h2>
          <p>A01 candidate evidence is available when a scan or report is generated with A01 checks.</p>
        </div>
        <div className="panel-message">No A01 Broken Access Control candidate evidence is attached to the selected result.</div>
      </article>
    )
  }
  const selected = [...evidence].sort((a, b) => (b.candidate_score || 0) - (a.candidate_score || 0))[0]
  const sensitiveRows = evidence.filter((item) => ['sensitive_resource_candidates', 'api_access_control_candidates', 'role_and_permission_indicators'].includes(item.rule_group || ''))
  return (
    <article className="panel panel--wide a01-panel">
      <div className="panel-heading">
        <div>
          <h2>A01 Broken Access Control</h2>
          <p>Access-control candidates, object identifier indicators, tenant boundary indicators, admin surface indicators, and manual validation planning.</p>
        </div>
      </div>
      <A01SummaryCards summary={summary} />
      <p className="panel-message">Candidate requiring manual validation. Authorised test accounts only; do not access real user data; no auth bypass automation performed.</p>
      <h3>Object ID Candidates</h3>
      <A01ObjectIdCandidateTable items={evidence} />
      <h3>Admin and Function Surfaces</h3>
      <A01AdminSurfaceTable items={evidence} />
      <h3>Tenant Boundary Candidates</h3>
      <A01TenantBoundaryPanel items={evidence} />
      <h3>Sensitive Resource, API, Role, and Permission Indicators</h3>
      {!sensitiveRows.length ? <div className="panel-message">No sensitive resource, API, role, or permission indicators are attached to this result.</div> : (
        <div className="a01-list">
          {sensitiveRows.map((item) => (
            <div className="a01-list-item" key={item.evidence_id}>
              <strong>{item.title || item.access_control_candidate_type}</strong>
              <span>{item.affected_url || 'endpoint unavailable'}</span>
              <small>{item.safe_evidence_summary || 'manual validation required'}; score {item.candidate_score || 0}</small>
            </div>
          ))}
        </div>
      )}
      <h3>Manual Test Planner</h3>
      <A01ManualTestPlanner selected={selected} />
      <h3>Evidence Template</h3>
      <A01EvidenceTemplatePanel selected={selected} />
      <h3>Recommendations</h3>
      <A01RecommendationPanel summary={summary} />
    </article>
  )
}
