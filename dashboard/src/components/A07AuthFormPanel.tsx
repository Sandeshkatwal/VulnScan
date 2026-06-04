import type { A07AuthenticationEvidenceItem } from '../types/api'
import { A07ConfidenceBadge } from './A07ConfidenceBadge'

export function A07AuthFormPanel({ items }: { items: A07AuthenticationEvidenceItem[] }) {
  const rows = items.filter((item) => item.rule_group === 'auth_form_indicators')
  if (!rows.length) return <div className="panel-message">No authentication form indicators available.</div>
  return (
    <div className="table-shell">
      <table>
        <thead><tr><th>URL</th><th>Password Field</th><th>CSRF-like Field</th><th>Action Scheme</th><th>Remember-me</th><th>Confidence</th><th>Manual Validation Note</th></tr></thead>
        <tbody>
          {rows.map((item) => (
            <tr key={item.evidence_id}>
              <td>{item.affected_url}</td>
              <td>{String(item.password_field_detected ?? false)}</td>
              <td>{String(item.csrf_like_field_detected ?? false)}</td>
              <td>{item.form_action_scheme}</td>
              <td>{String(item.remember_me_checkbox ?? false)}</td>
              <td><A07ConfidenceBadge confidence={item.confidence} /></td>
              <td>{item.manual_validation_required ? 'Manual validation required' : 'Evidence metadata only'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
