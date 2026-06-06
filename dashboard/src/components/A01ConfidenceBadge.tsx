export function A01ConfidenceBadge({ confidence }: { confidence?: string }) {
  const value = confidence || 'Low'
  const tone = value.toLowerCase() === 'high' ? 'high' : value.toLowerCase() === 'medium' ? 'medium' : 'low'
  return <span className={`a01-badge a01-badge--${tone}`}>{value}</span>
}
