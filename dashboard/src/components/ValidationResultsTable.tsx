import type { SafeValidationResult, SafeValidationSkipped } from '../types/api'
import { ValidationStatusBadge } from './ValidationStatusBadge'

interface ValidationResultsTableProps {
  results: SafeValidationResult[]
  skipped: SafeValidationSkipped[]
  onSelectResult: (result: SafeValidationResult) => void
}

export function ValidationResultsTable({ results, skipped, onSelectResult }: ValidationResultsTableProps) {
  return (
    <div className="table-shell">
      <table>
        <thead><tr><th>URL</th><th>Check</th><th>Status</th><th>Confidence</th><th>Manual validation</th></tr></thead>
        <tbody>
          {results.map((item) => (
            <tr key={`${item.url}-${item.check_name}`} onClick={() => onSelectResult(item)}>
              <td>{item.url}</td>
              <td>{item.check_name}</td>
              <td><ValidationStatusBadge status={item.status} indicator={item.indicator_found} /></td>
              <td>{item.confidence}</td>
              <td>{item.manual_validation_note}</td>
            </tr>
          ))}
          {skipped.map((item) => (
            <tr key={`${item.url}-${item.reason}`}>
              <td>{item.url}</td>
              <td>{item.candidate_type}</td>
              <td>skipped</td>
              <td>Low</td>
              <td>{item.reason} {item.scope_reason}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
