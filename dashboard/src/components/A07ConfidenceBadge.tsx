export function A07ConfidenceBadge({ confidence }: { confidence?: string }) {
  const value = confidence || 'Low'
  const tone = value.toLowerCase() === 'high' ? 'high' : value.toLowerCase() === 'medium' ? 'medium' : 'low'
  return <span className={`a07-confidence a07-confidence--${tone}`}>{value}</span>
}
