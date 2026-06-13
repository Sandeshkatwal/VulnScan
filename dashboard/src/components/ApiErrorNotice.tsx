interface ApiErrorNoticeProps {
  error?: string | null
  onRetry: () => void
}

export function ApiErrorNotice({ error, onRetry }: ApiErrorNoticeProps) {
  if (!error) return null
  return (
    <section className="api-error-notice" aria-label="API error notice">
      <strong>API Error Handling</strong>
      <span>{error}</span>
      <button className="secondary-button" type="button" onClick={onRetry}>Retry</button>
    </section>
  )
}
