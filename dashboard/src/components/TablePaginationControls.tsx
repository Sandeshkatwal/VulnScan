import type { PagePagination } from '../types/api'

interface Props {
  pagination?: PagePagination | null
  disabled?: boolean
  pageSize?: number
  onPageChange?: (page: number) => void
  onPageSizeChange?: (pageSize: number) => void
}

export function TablePaginationControls({
  pagination,
  disabled = false,
  pageSize = 25,
  onPageChange,
  onPageSizeChange,
}: Props) {
  const page = pagination?.page ?? 1
  const totalPages = pagination?.total_pages ?? 0
  const total = pagination?.total ?? 0

  return (
    <div className="table-pagination-controls">
      <span>{total} total</span>
      <span>Page {page}{totalPages ? ` of ${totalPages}` : ''}</span>
      <label>
        <span>Page size</span>
        <select
          value={pageSize}
          disabled={disabled}
          onChange={(event) => onPageSizeChange?.(Number(event.target.value))}
        >
          {[10, 25, 50, 100].map((size) => (
            <option key={size} value={size}>{size}</option>
          ))}
        </select>
      </label>
      <button
        className="secondary-button"
        type="button"
        disabled={disabled || !pagination?.has_previous}
        onClick={() => onPageChange?.(pagination?.previous_page ?? Math.max(1, page - 1))}
      >
        Previous
      </button>
      <button
        className="secondary-button"
        type="button"
        disabled={disabled || !pagination?.has_next}
        onClick={() => onPageChange?.(pagination?.next_page ?? page + 1)}
      >
        Next
      </button>
    </div>
  )
}
