import type { ReactNode } from 'react'

interface Props {
  search?: string
  placeholder?: string
  disabled?: boolean
  children?: ReactNode
  onSearchChange?: (value: string) => void
}

export function TableToolbar({
  search = '',
  placeholder = 'Search',
  disabled = false,
  children,
  onSearchChange,
}: Props) {
  return (
    <div className="table-toolbar">
      <label>
        <span>Search</span>
        <input
          value={search}
          placeholder={placeholder}
          disabled={disabled}
          onChange={(event) => onSearchChange?.(event.target.value)}
        />
      </label>
      <div className="table-toolbar__actions">{children}</div>
    </div>
  )
}
