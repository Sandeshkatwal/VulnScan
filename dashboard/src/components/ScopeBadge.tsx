interface ScopeBadgeProps {
  inScope?: boolean | null
}

export function ScopeBadge({ inScope }: ScopeBadgeProps) {
  if (inScope === true) return <span className="scope-badge scope-badge--in">In Scope</span>
  if (inScope === false) return <span className="scope-badge scope-badge--out">Out of Scope</span>
  return <span className="scope-badge">Not Checked</span>
}
