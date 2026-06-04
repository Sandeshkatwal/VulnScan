export function A10ConfidenceBadge({ confidence }: { confidence?: string }) {
  const level = (confidence || 'Low').toLowerCase()
  return <span className={`a10-confidence a10-confidence--${level}`}>{confidence || 'Low'}</span>
}
