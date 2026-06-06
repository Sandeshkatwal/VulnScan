import type { A01AccessControlSummary } from '../types/api'

export function A01SummaryCards({ summary }: { summary: A01AccessControlSummary }) {
  const cards = [
    ['Total A01 candidates', summary.total_evidence_items || 0],
    ['High-interest candidates', summary.high_interest_count || 0],
    ['Object ID candidates', summary.object_id_candidate_count || 0],
    ['Tenant boundary candidates', summary.tenant_boundary_candidate_count || 0],
    ['Admin/function candidates', summary.function_level_candidate_count || 0],
    ['Export/download candidates', summary.sensitive_resource_candidate_count || 0],
    ['Role/permission indicators', summary.role_permission_indicator_count || 0],
    ['Manual validation required', summary.manual_validation_required_count || 0],
  ]
  return (
    <div className="a01-summary-grid">
      {cards.map(([label, value]) => (
        <div className="metric-card" key={label}>
          <span>{label}</span>
          <strong>{value}</strong>
        </div>
      ))}
    </div>
  )
}
