import type { BugBountyReconResult, BugBountyReconSkipped } from '../types/api'
import { ReconStatusBadge } from './ReconStatusBadge'

interface ReconResultsTableProps {
  results: BugBountyReconResult[]
  skipped: BugBountyReconSkipped[]
}

function technologies(result: BugBountyReconResult): string {
  return (result.technology_hints || []).map((hint) => hint.name).filter(Boolean).join(', ') || '-'
}

export function ReconResultsTable({ results, skipped }: ReconResultsTableProps) {
  return (
    <div className="recon-table-stack">
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Target</th>
              <th>Probe URL</th>
              <th>Status</th>
              <th>Title</th>
              <th>Server</th>
              <th>Technologies</th>
              <th>Scope</th>
              <th>Time</th>
              <th>Final URL</th>
            </tr>
          </thead>
          <tbody>
            {results.map((result, index) => (
              <tr key={`${result.probe_url || result.target}-${index}`}>
                <td>{result.target || '-'}</td>
                <td>{result.probe_url || '-'}</td>
                <td><ReconStatusBadge live={result.live} statusCode={result.status_code} errorCode={result.error_code} inScope={result.in_scope} /></td>
                <td>{result.page_title || '-'}</td>
                <td>{result.server_header || '-'}</td>
                <td>{technologies(result)}</td>
                <td>{result.in_scope ? 'In scope' : 'Out of scope'}</td>
                <td>{result.response_time_ms ?? 0} ms</td>
                <td>{result.final_url || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!results.length ? <div className="empty-state">No probe results yet.</div> : null}
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Skipped Target</th>
              <th>Probe URL</th>
              <th>Reason</th>
              <th>Scope Reason</th>
            </tr>
          </thead>
          <tbody>
            {skipped.map((item, index) => (
              <tr key={`${item.probe_url || item.target}-${index}`}>
                <td>{item.target || '-'}</td>
                <td>{item.probe_url || '-'}</td>
                <td>{item.reason || '-'}</td>
                <td>{item.scope_reason || item.matched_rule || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!skipped.length ? <div className="empty-state">No skipped targets.</div> : null}
      </div>
    </div>
  )
}
