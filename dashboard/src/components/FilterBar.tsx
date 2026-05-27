import type { FindingFilters } from '../types/api'

interface FilterBarProps {
  filters: FindingFilters
  onChange: (filters: FindingFilters) => void
  onApply: () => void
  onClear: () => void
  disabled?: boolean
}

const severityOptions = ['', 'Critical', 'High', 'Medium', 'Low', 'Informational']
const priorityOptions = ['', 'Fix First', 'Fix Soon', 'Monitor', 'Informational']

export function FilterBar({ filters, onChange, onApply, onClear, disabled = false }: FilterBarProps) {
  function setFilter(field: keyof FindingFilters, value: string) {
    onChange({ ...filters, [field]: value })
  }

  return (
    <div className="filter-bar">
      <label>
        <span>Severity</span>
        <select
          value={filters.severity || ''}
          disabled={disabled}
          onChange={(event) => setFilter('severity', event.target.value)}
        >
          {severityOptions.map((option) => (
            <option key={option || 'any'} value={option}>
              {option || 'Any'}
            </option>
          ))}
        </select>
      </label>
      <label>
        <span>Source</span>
        <input
          type="text"
          value={filters.source || ''}
          disabled={disabled}
          onChange={(event) => setFilter('source', event.target.value)}
        />
      </label>
      <label>
        <span>Category</span>
        <input
          type="text"
          value={filters.category || ''}
          disabled={disabled}
          onChange={(event) => setFilter('category', event.target.value)}
        />
      </label>
      <label>
        <span>Priority</span>
        <select
          value={filters.priority_label || ''}
          disabled={disabled}
          onChange={(event) => setFilter('priority_label', event.target.value)}
        >
          {priorityOptions.map((option) => (
            <option key={option || 'any'} value={option}>
              {option || 'Any'}
            </option>
          ))}
        </select>
      </label>
      <label>
        <span>Min priority</span>
        <input
          type="number"
          min="0"
          max="100"
          value={filters.min_priority_score || ''}
          disabled={disabled}
          onChange={(event) => setFilter('min_priority_score', event.target.value)}
        />
      </label>
      <label>
        <span>Min risk</span>
        <input
          type="number"
          min="0"
          max="100"
          value={filters.min_risk_score || ''}
          disabled={disabled}
          onChange={(event) => setFilter('min_risk_score', event.target.value)}
        />
      </label>
      <div className="filter-actions">
        <button className="secondary-button" type="button" onClick={onApply} disabled={disabled}>
          Apply
        </button>
        <button className="ghost-button" type="button" onClick={onClear} disabled={disabled}>
          Clear
        </button>
      </div>
    </div>
  )
}
