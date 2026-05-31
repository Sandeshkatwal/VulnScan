import type { EndpointResult } from '../types/api'
import { EndpointRiskBadge } from './EndpointRiskBadge'

interface EndpointTableProps {
  results: EndpointResult[]
}

export function EndpointTable({ results }: EndpointTableProps) {
  if (!results.length) {
    return <div className="panel-message">No endpoint candidates have been analysed yet.</div>
  }
  return (
    <div className="table-shell">
      <table>
        <thead>
          <tr>
            <th>URL</th>
            <th>Category</th>
            <th>Params</th>
            <th>Score</th>
            <th>Label</th>
            <th>Reasons</th>
            <th>In scope</th>
          </tr>
        </thead>
        <tbody>
          {results.map((item) => (
            <tr key={`${item.normalised_url}-${item.candidate_score}`}>
              <td>{item.normalised_url || item.path}</td>
              <td>{item.endpoint_category || 'unknown'}</td>
              <td>{item.parameters?.length || 0}</td>
              <td>{item.candidate_score || 0}</td>
              <td><EndpointRiskBadge label={item.candidate_label} /></td>
              <td>{item.candidate_reasons?.join(', ') || 'Manual Validation Required'}</td>
              <td>{item.in_scope ? 'Yes' : 'No'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
