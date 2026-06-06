import type { A01AccessControlEvidenceItem } from '../types/api'

export function A01TenantBoundaryPanel({ items }: { items: A01AccessControlEvidenceItem[] }) {
  const rows = items.filter((item) => item.rule_group === 'tenant_boundary_candidates')
  if (!rows.length) return <div className="panel-message">No tenant boundary candidates are attached to this result.</div>
  return (
    <div className="a01-list">
      {rows.map((item) => (
        <div className="a01-list-item" key={item.evidence_id}>
          <strong>{item.affected_parameter || item.object_type_hint || item.title}</strong>
          <span>{item.affected_url || 'endpoint unavailable'}</span>
          <small>{item.manual_test_plan_id || 'tenant_boundary_review'}; authorised test tenants only; do not access real user data.</small>
        </div>
      ))}
    </div>
  )
}
