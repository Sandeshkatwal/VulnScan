import type { BugBountyScopeSummary } from '../types/api'

interface ScopeProgramCardProps {
  scope: BugBountyScopeSummary
  selected?: boolean
  onSelect: (scope: BugBountyScopeSummary) => void
}

export function ScopeProgramCard({ scope, selected = false, onSelect }: ScopeProgramCardProps) {
  return (
    <button
      className={selected ? 'scope-program-card scope-program-card--selected' : 'scope-program-card'}
      type="button"
      onClick={() => onSelect(scope)}
    >
      <span>{scope.program_name || 'Unnamed program'}</span>
      <strong>{scope.platform || 'local'}</strong>
      <small>Version {scope.scope_version || 'unknown'} · {scope.last_updated || 'unknown update'}</small>
      <small>{scope.policy_url || 'No policy URL'}</small>
    </button>
  )
}
