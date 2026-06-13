import { useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import type { PagePagination } from '../types/api'
import { TablePaginationControls } from './TablePaginationControls'
import { TableToolbar } from './TableToolbar'

export interface PaginatedTableColumn<T> {
  key: string
  header: ReactNode
  render?: (item: T) => ReactNode
}

interface Props<T> {
  items: T[]
  columns: PaginatedTableColumn<T>[]
  getRowKey: (item: T, index: number) => string
  pagination?: PagePagination | null
  loading?: boolean
  error?: string | null
  emptyMessage?: string
  searchable?: boolean
  onSearchChange?: (value: string) => void
  onPageChange?: (page: number) => void
  onPageSizeChange?: (pageSize: number) => void
}

export function PaginatedTable<T extends Record<string, unknown>>({
  items,
  columns,
  getRowKey,
  pagination,
  loading = false,
  error,
  emptyMessage = 'No records found.',
  searchable = false,
  onSearchChange,
  onPageChange,
  onPageSizeChange,
}: Props<T>) {
  const [localSearch, setLocalSearch] = useState('')
  const displayedItems = useMemo(() => {
    if (onSearchChange || !localSearch) return items
    const needle = localSearch.toLowerCase()
    return items.filter((item) => JSON.stringify(item).toLowerCase().includes(needle))
  }, [items, localSearch, onSearchChange])

  if (loading) return <div className="panel-message">Loading records...</div>
  if (error) return <div className="panel-message panel-message--error">{error}</div>

  return (
    <div className="paginated-table">
      {searchable ? (
        <TableToolbar
          search={localSearch}
          disabled={loading}
          onSearchChange={(value) => {
            setLocalSearch(value)
            onSearchChange?.(value)
          }}
        />
      ) : null}
      {displayedItems.length === 0 ? (
        <div className="panel-message">{emptyMessage}</div>
      ) : (
        <div className="table-wrap">
          <table className="findings-table">
            <thead>
              <tr>
                {columns.map((column) => <th key={column.key}>{column.header}</th>)}
              </tr>
            </thead>
            <tbody>
              {displayedItems.map((item, index) => (
                <tr key={getRowKey(item, index)}>
                  {columns.map((column) => (
                    <td key={column.key}>{column.render ? column.render(item) : String(item[column.key] ?? '')}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <TablePaginationControls
        pagination={pagination}
        pageSize={pagination?.page_size ?? 25}
        disabled={loading}
        onPageChange={onPageChange}
        onPageSizeChange={onPageSizeChange}
      />
    </div>
  )
}
