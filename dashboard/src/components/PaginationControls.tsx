import type { Pagination } from '../types/api'

interface PaginationControlsProps {
  pagination?: Pagination | null
  limit: number
  offset: number
  disabled?: boolean
  onChange: (limit: number, offset: number) => void
}

export function PaginationControls({
  pagination,
  limit,
  offset,
  disabled = false,
  onChange,
}: PaginationControlsProps) {
  const total = pagination?.total
  const returned = pagination?.returned ?? 0
  const page = Math.floor(offset / limit) + 1

  return (
    <div className="pagination-controls">
      <div>
        <span>{returned} returned</span>
        {typeof total === 'number' ? <span>{total} total</span> : null}
        <span>Page {page}</span>
      </div>
      <label>
        <span>Page size</span>
        <select
          value={limit}
          disabled={disabled}
          onChange={(event) => onChange(Number(event.target.value), 0)}
        >
          {[10, 20, 50].map((size) => (
            <option key={size} value={size}>
              {size}
            </option>
          ))}
        </select>
      </label>
      <button
        className="secondary-button"
        type="button"
        disabled={disabled || !pagination?.has_previous}
        onClick={() => onChange(limit, Math.max(0, offset - limit))}
      >
        Previous
      </button>
      <button
        className="secondary-button"
        type="button"
        disabled={disabled || !pagination?.has_next}
        onClick={() => onChange(limit, pagination?.next_offset ?? offset + limit)}
      >
        Next
      </button>
    </div>
  )
}
