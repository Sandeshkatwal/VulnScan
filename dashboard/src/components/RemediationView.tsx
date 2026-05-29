import { useCallback, useEffect, useState } from 'react'
import { getRemediation, getRemediationRecord, getRemediationSummary, updateRemediation } from '../api/client'
import type { Pagination, RemediationQuery, RemediationRecord, RemediationSummary, RemediationUpdatePayload } from '../types/api'
import { formatDateTime, formatValue } from '../utils/format'
import { PaginationControls } from './PaginationControls'
import { RemediationStatusBadge } from './RemediationStatusBadge'
import { RemediationUpdateForm } from './RemediationUpdateForm'

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Request failed.'
}

const defaultFilters: RemediationQuery = { limit: 20, offset: 0 }

export function RemediationView({ apiOnline = true }: { apiOnline?: boolean }) {
  const [records, setRecords] = useState<RemediationRecord[]>([])
  const [summary, setSummary] = useState<RemediationSummary | null>(null)
  const [pagination, setPagination] = useState<Pagination | null>(null)
  const [filters, setFilters] = useState<RemediationQuery>(defaultFilters)
  const [selectedRecord, setSelectedRecord] = useState<RemediationRecord | null>(null)
  const [loading, setLoading] = useState(false)
  const [updating, setUpdating] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)

  const loadRemediation = useCallback(async (nextFilters: RemediationQuery = filters) => {
    if (!apiOnline) return
    setLoading(true)
    setError(null)
    try {
      const [recordsResponse, summaryResponse] = await Promise.all([
        getRemediation(nextFilters),
        getRemediationSummary(),
      ])
      setRecords(recordsResponse.records)
      setPagination(recordsResponse.pagination || null)
      setSummary(summaryResponse)
      setSelectedRecord((current) => {
        if (current?.finding_key && recordsResponse.records.some((record) => record.finding_key === current.finding_key)) return current
        return recordsResponse.records[0] || null
      })
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }, [apiOnline, filters])

  useEffect(() => {
    void loadRemediation()
  }, [loadRemediation])

  async function handleUpdate(findingKey: string, payload: RemediationUpdatePayload) {
    setUpdating(true)
    setMessage(null)
    setError(null)
    try {
      const response = await updateRemediation(findingKey, payload)
      setSelectedRecord(response.record || selectedRecord)
      setMessage('Remediation tracking updated.')
      await loadRemediation(filters)
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setUpdating(false)
    }
  }

  function updateFilter(key: keyof RemediationQuery, value: string) {
    setFilters((current) => ({ ...current, [key]: value || undefined, offset: 0 }))
  }

  function applyFilters() {
    void loadRemediation({ ...filters, offset: 0 })
  }

  function clearFilters() {
    setFilters(defaultFilters)
    void loadRemediation(defaultFilters)
  }

  function updatePage(limit: number, offset: number) {
    const next = { ...filters, limit, offset }
    setFilters(next)
    void loadRemediation(next)
  }

  async function selectRecord(record: RemediationRecord) {
    setSelectedRecord(record)
    setError(null)
    if (!record.finding_key) return
    try {
      const response = await getRemediationRecord(record.finding_key)
      setSelectedRecord(response.record || record)
    } catch (caught) {
      setError(errorMessage(caught))
    }
  }

  if (!apiOnline) {
    return <div className="empty-state">API offline. Remediation tracking will load when the local API is reachable.</div>
  }

  return (
    <div className="remediation-view">
      <div className="remediation-summary-grid">
        <SummaryCard label="Open" value={summary?.open_count} />
        <SummaryCard label="In Progress" value={summary?.in_progress_count} />
        <SummaryCard label="Fixed" value={summary?.fixed_count} />
        <SummaryCard label="Accepted Risk" value={summary?.accepted_risk_count} />
        <SummaryCard label="False Positive" value={summary?.false_positive_count} />
        <SummaryCard label="Overdue" value={summary?.overdue_count} />
      </div>

      <div className="remediation-filter-bar">
        <label><span>Status</span><select value={filters.status || ''} onChange={(event) => updateFilter('status', event.target.value)}>
          <option value="">All</option>
          <option value="open">Open</option>
          <option value="in_progress">In Progress</option>
          <option value="fixed">Fixed</option>
          <option value="accepted_risk">Accepted Risk</option>
          <option value="false_positive">False Positive</option>
        </select></label>
        <label><span>Severity</span><input value={filters.severity || ''} onChange={(event) => updateFilter('severity', event.target.value)} /></label>
        <label><span>Source</span><input value={filters.source || ''} onChange={(event) => updateFilter('source', event.target.value)} /></label>
        <label><span>Priority</span><input value={filters.priority_label || ''} onChange={(event) => updateFilter('priority_label', event.target.value)} /></label>
        <label><span>Target</span><input value={filters.target || ''} onChange={(event) => updateFilter('target', event.target.value)} /></label>
        <div className="button-row">
          <button className="secondary-button" type="button" onClick={applyFilters} disabled={loading}>Apply</button>
          <button className="ghost-button" type="button" onClick={clearFilters} disabled={loading}>Clear</button>
          <button className="ghost-button" type="button" onClick={() => void loadRemediation()} disabled={loading}>Refresh</button>
        </div>
      </div>

      {message ? <div className="success-message">{message}</div> : null}
      {error ? <div className="panel-message panel-message--error">{error}</div> : null}

      <div className="remediation-layout">
        <div className="table-wrap">
          {loading ? <div className="panel-message">Loading remediation records...</div> : null}
          {!loading && records.length === 0 ? <div className="empty-state">No remediation records yet. Open a finding and update its remediation status.</div> : null}
          {records.length ? (
            <table className="remediation-table">
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Target</th>
                  <th>Severity</th>
                  <th>Priority</th>
                  <th>Source</th>
                  <th>Status</th>
                  <th>Owner</th>
                  <th>Due date</th>
                  <th>Updated</th>
                </tr>
              </thead>
              <tbody>
                {records.map((record) => (
                  <tr key={record.finding_key} className={selectedRecord?.finding_key === record.finding_key ? 'selected-row' : undefined} onClick={() => void selectRecord(record)}>
                    <td>{formatValue(record.title)}</td>
                    <td>{formatValue(record.target)}</td>
                    <td>{formatValue(record.severity)}</td>
                    <td>{formatValue(record.priority_label)}</td>
                    <td>{formatValue(record.source)}</td>
                    <td><RemediationStatusBadge status={record.status} /></td>
                    <td>{formatValue(record.owner)}</td>
                    <td>{formatValue(record.due_date)}</td>
                    <td>{formatDateTime(record.updated_at || undefined)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : null}
          <PaginationControls pagination={pagination} limit={Number(filters.limit || 20)} offset={Number(filters.offset || 0)} disabled={loading} onChange={updatePage} />
        </div>

        <aside className="remediation-side-panel">
          <h3>Update Tracking</h3>
          <p>Tracking only. VulScan does not patch systems, restart services, or run commands on targets.</p>
          <RemediationUpdateForm record={selectedRecord} findingKey={selectedRecord?.finding_key} loading={updating} onSubmit={handleUpdate} />
          {selectedRecord?.history?.length ? (
            <div className="remediation-history">
              <h4>History</h4>
              {selectedRecord.history.map((item, index) => (
                <div key={`${item.updated_at}-${index}`}>
                  <strong>{formatValue(item.old_status)} to {formatValue(item.new_status)}</strong>
                  <span>{formatDateTime(item.updated_at || undefined)}</span>
                  <p>{formatValue(item.note)}</p>
                </div>
              ))}
            </div>
          ) : <div className="context-card__message">No remediation history available.</div>}
        </aside>
      </div>
    </div>
  )
}

function SummaryCard({ label, value }: { label: string; value?: number }) {
  return (
    <div className="remediation-summary-card">
      <span>{label}</span>
      <strong>{value ?? 0}</strong>
    </div>
  )
}
