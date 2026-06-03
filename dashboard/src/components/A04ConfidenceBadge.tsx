export function A04ConfidenceBadge({ confidence }: { confidence?: string }) {
  const value = confidence || 'Low'
  const tone = value.toLowerCase() === 'high' ? 'high' : value.toLowerCase() === 'medium' ? 'medium' : 'low'
  return <span className={`a04-confidence a04-confidence--${tone}`}>{value}</span>
}
