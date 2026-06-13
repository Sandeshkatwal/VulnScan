import type { Finding } from '../types/api'
import { formatValue, getCve, getCvss, getEpss, getExploitAvailable } from '../utils/format'
import { FindingBadge } from './FindingBadge'
import { PaginatedTable, type PaginatedTableColumn } from './PaginatedTable'

interface FindingsTableProps {
  findings: Finding[]
  loading?: boolean
  error?: string | null
  sortBy?: string
  sortOrder?: string
  onSort?: (sortBy: string) => void
  onSelectFinding?: (finding: Finding) => void
}

const sortableFields = new Set(['severity', 'risk_score', 'priority_score', 'title', 'source', 'category'])

export function FindingsTable({
  findings,
  loading = false,
  error,
  sortBy,
  sortOrder,
  onSort,
  onSelectFinding,
}: FindingsTableProps) {
  if (loading) {
    return <PaginatedTable items={[]} columns={[]} getRowKey={() => 'loading'} loading />
  }

  if (error) {
    return <div className="panel-message panel-message--error">{error}</div>
  }

  function header(label: string, field?: string) {
    const active = field && sortBy === field
    const suffix = active ? (sortOrder === 'asc' ? ' up' : ' down') : ''
    if (!field || !sortableFields.has(field)) return label
    return (
        <button className="table-sort-button" type="button" onClick={() => onSort?.(field)}>
          {label}{suffix}
        </button>
    )
  }

  const columns: PaginatedTableColumn<Finding>[] = [
    { key: 'title', header: header('Title', 'title'), render: (finding) => formatValue(finding.title) },
    { key: 'severity', header: header('Severity', 'severity'), render: (finding) => <FindingBadge type="severity" value={finding.severity} /> },
    { key: 'source', header: header('Source', 'source'), render: (finding) => formatValue(finding.source) },
    { key: 'category', header: header('Category', 'category'), render: (finding) => formatValue(finding.category) },
    { key: 'risk_score', header: header('Risk', 'risk_score'), render: (finding) => formatValue(finding.risk_score) },
    { key: 'priority_score', header: header('Priority Score', 'priority_score'), render: (finding) => formatValue(finding.priority_score) },
    { key: 'priority_label', header: 'Priority', render: (finding) => <FindingBadge type="priority" value={finding.priority_label} /> },
    { key: 'cve', header: 'CVE', render: (finding) => getCve(finding) },
    { key: 'cvss', header: 'CVSS', render: (finding) => getCvss(finding) },
    { key: 'epss', header: 'EPSS', render: (finding) => getEpss(finding) },
    { key: 'exploit', header: 'Exploit', render: (finding) => <FindingBadge type="exploit" value={getExploitAvailable(finding)} /> },
    {
      key: 'action',
      header: 'Action',
      render: (finding) => (
        <button className="ghost-button compact-button" type="button" onClick={() => onSelectFinding?.(finding)}>
          View Details
        </button>
      ),
    },
  ]

  return (
    <PaginatedTable
      items={findings}
      columns={columns}
      getRowKey={(finding, index) => `${finding.finding_id || finding.title || 'finding'}-${index}`}
      emptyMessage="No findings match the current filters."
    />
  )
}
