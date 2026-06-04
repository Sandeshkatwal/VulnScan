import type { A10ErrorHandlingEvidenceItem } from '../types/api'
import { A10ConfidenceBadge } from './A10ConfidenceBadge'

export function A10FrameworkIndicatorPanel({ items }: { items: A10ErrorHandlingEvidenceItem[] }) {
  const rows = items.filter((item) => item.rule_group === 'framework_error_indicators' || item.framework_hint)
  if (!rows.length) return <div className="panel-message">No framework debug indicators are attached to the selected result.</div>
  return (
    <div className="table-shell">
      <table>
        <thead><tr><th>Framework Hint</th><th>Pattern Matched</th><th>URL</th><th>Confidence</th></tr></thead>
        <tbody>
          {rows.map((item) => (
            <tr key={item.evidence_id || `${item.rule_id}-${item.affected_url}`}>
              <td>{item.framework_hint || item.title || '-'}</td>
              <td>{item.pattern_matched || item.observed_pattern || item.rule_id || '-'}</td>
              <td>{item.affected_url || '-'}</td>
              <td><A10ConfidenceBadge confidence={item.confidence} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
