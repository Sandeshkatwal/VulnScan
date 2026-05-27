import type { ScanSummary } from '../types/api'

interface ScansTableProps {
  scans: ScanSummary[]
  loading?: boolean
  error?: string | null
}

function formatDate(value?: string): string {
  if (!value) return 'n/a'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function getScanTime(scan: ScanSummary): string {
  return scan.scan_time || scan.scan_start_time || scan.created_at || ''
}

function getTarget(scan: ScanSummary): string {
  return scan.target || scan.host || 'n/a'
}

function getFindingsCount(scan: ScanSummary): string {
  const count = scan.findings_count ?? scan.finding_count ?? scan.total_findings
  return count === null || count === undefined ? 'n/a' : String(count)
}

export function ScansTable({ scans, loading = false, error }: ScansTableProps) {
  if (loading) {
    return <div className="panel-message">Loading recent scans...</div>
  }

  if (error) {
    return <div className="panel-message panel-message--error">{error}</div>
  }

  if (scans.length === 0) {
    return <div className="panel-message">No saved scans found yet.</div>
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Scan ID</th>
            <th>Target</th>
            <th>Scan Time</th>
            <th>Findings</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.scan_id || `${getTarget(scan)}-${getScanTime(scan)}`}>
              <td className="mono">{scan.scan_id || 'n/a'}</td>
              <td>{getTarget(scan)}</td>
              <td>{formatDate(getScanTime(scan))}</td>
              <td>{getFindingsCount(scan)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
