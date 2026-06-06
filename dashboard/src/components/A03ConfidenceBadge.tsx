export function A03ConfidenceBadge({ confidence }: { confidence?: string }) {
  const tone = (confidence || 'Low').toLowerCase()
  return <span className={`confidence-badge confidence-badge--${tone}`}>{confidence || 'Low'}</span>
}
