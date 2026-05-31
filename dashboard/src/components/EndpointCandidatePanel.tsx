import type { EndpointSkipped, Finding } from '../types/api'
import { ReconFindingPanel } from './ReconFindingPanel'

interface EndpointCandidatePanelProps {
  skipped: EndpointSkipped[]
  findings: Finding[]
}

export function EndpointCandidatePanel({ skipped, findings }: EndpointCandidatePanelProps) {
  return (
    <div className="stacked-panel-content">
      <ReconFindingPanel findings={findings} />
      <div>
        <h3>Skipped URLs</h3>
        {!skipped.length ? (
          <div className="panel-message">No endpoint URLs were skipped.</div>
        ) : (
          <div className="table-shell">
            <table>
              <thead>
                <tr>
                  <th>URL</th>
                  <th>Reason</th>
                  <th>Scope Reason</th>
                </tr>
              </thead>
              <tbody>
                {skipped.map((item) => (
                  <tr key={`${item.original_url}-${item.reason}`}>
                    <td>{item.original_url}</td>
                    <td>{item.reason}</td>
                    <td>{item.scope_reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
