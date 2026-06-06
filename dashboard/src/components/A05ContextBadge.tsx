export function A05ContextBadge({ value }: { value?: string }) {
  const context = value || 'unknown'
  return <span className={`a05-context a05-context--${context}`}>{context.replaceAll('_', ' ')}</span>
}
