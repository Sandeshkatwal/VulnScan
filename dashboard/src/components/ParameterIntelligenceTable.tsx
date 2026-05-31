import type { ParameterResult } from '../types/api'

interface ParameterIntelligenceTableProps {
  results: ParameterResult[]
}

export function ParameterIntelligenceTable({ results }: ParameterIntelligenceTableProps) {
  if (!results.length) {
    return <div className="panel-message">No interesting parameter candidates were identified.</div>
  }
  return (
    <div className="table-shell">
      <table>
        <thead>
          <tr>
            <th>URL / Path</th>
            <th>Parameter</th>
            <th>Type</th>
            <th>Potential Issue</th>
            <th>Confidence</th>
            <th>Manual Validation Note</th>
          </tr>
        </thead>
        <tbody>
          {results.map((item) => (
            <tr key={`${item.url}-${item.parameter_name}-${item.parameter_type}`}>
              <td>{item.path || item.url}</td>
              <td>{item.parameter_name}</td>
              <td>{item.parameter_type}</td>
              <td>{item.potential_issue}</td>
              <td>{item.confidence}</td>
              <td>{item.manual_validation_note || 'Manual Validation Required'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
