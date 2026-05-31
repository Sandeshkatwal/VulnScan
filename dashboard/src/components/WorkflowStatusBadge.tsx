import type { WorkflowStepStatus } from '../types/api'

export function WorkflowStatusBadge({ status }: { status?: WorkflowStepStatus | string }) {
  const value = status || 'Not started'
  const tone = value === 'Completed' ? 'good' : value === 'Needs review' ? 'warn' : value === 'In progress' || value === 'Ready' ? 'info' : 'muted'
  return <span className={`workflow-status workflow-status--${tone}`}>{value}</span>
}
