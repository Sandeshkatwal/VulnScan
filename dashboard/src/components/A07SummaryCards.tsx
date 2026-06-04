import type { A07AuthenticationSummary } from '../types/api'

export function A07SummaryCards({ summary }: { summary?: A07AuthenticationSummary }) {
  const cards = [
    ['Total A07 evidence', summary?.total_evidence_items ?? 0],
    ['Strong indicators', summary?.strong_indicators_count ?? 0],
    ['Weak indicators', summary?.weak_indicators_count ?? 0],
    ['Auth endpoints', summary?.auth_endpoint_count ?? 0],
    ['Login forms', summary?.login_form_count ?? 0],
    ['Password reset', summary?.password_reset_endpoint_count ?? 0],
    ['Session cookies', summary?.session_cookie_indicator_count ?? 0],
    ['Remember-me', summary?.remember_me_indicator_count ?? 0],
    ['Manual validation', summary?.manual_validation_required_count ?? 0],
  ]
  return <div className="a07-summary-grid">{cards.map(([label, value]) => <div className="summary-card" key={label}><span>{label}</span><strong>{value}</strong></div>)}</div>
}
