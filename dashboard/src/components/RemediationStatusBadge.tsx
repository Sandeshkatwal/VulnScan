import type { RemediationStatus } from '../types/api'

const LABELS: Record<RemediationStatus, string> = {
  open: 'Open',
  in_progress: 'In Progress',
  fixed: 'Fixed',
  accepted_risk: 'Accepted Risk',
  false_positive: 'False Positive',
}

function tone(status?: string | null): string {
  if (status === 'fixed') return 'good'
  if (status === 'in_progress') return 'warn'
  if (status === 'accepted_risk' || status === 'false_positive') return 'neutral'
  return 'bad'
}

export function remediationStatusLabel(status?: string | null): string {
  const key = String(status || 'open') as RemediationStatus
  return LABELS[key] || 'Open'
}

export function RemediationStatusBadge({ status }: { status?: string | null }) {
  return <span className={`remediation-status-badge remediation-status-badge--${tone(status)}`}>{remediationStatusLabel(status)}</span>
}
