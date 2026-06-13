interface RetryPanelProps {
  message: string
  onRetry: () => void
  retryLabel?: string
}

export function RetryPanel({ message, onRetry, retryLabel = 'Retry' }: RetryPanelProps) {
  return (
    <div className="retry-panel">
      <p>{message}</p>
      <button className="secondary-button" type="button" onClick={onRetry}>{retryLabel}</button>
    </div>
  )
}
