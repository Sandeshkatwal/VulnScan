interface ReconStatusBadgeProps {
  live?: boolean
  inScope?: boolean
  statusCode?: number | null
  errorCode?: string
}

export function ReconStatusBadge({ live, inScope, statusCode, errorCode }: ReconStatusBadgeProps) {
  if (inScope === false) return <span className="scope-badge scope-badge--out">Out of scope</span>
  if (errorCode) return <span className="scope-badge scope-badge--out">{errorCode}</span>
  if (live) return <span className="scope-badge scope-badge--in">{statusCode || 'Live'}</span>
  return <span className="scope-badge">No response</span>
}
