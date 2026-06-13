interface SafeEmptyStateProps {
  title: string
  message: string
}

export function SafeEmptyState({ title, message }: SafeEmptyStateProps) {
  return (
    <div className="safe-empty-state">
      <strong>{title}</strong>
      <span>{message}</span>
    </div>
  )
}
