import { AlertTriangle } from 'lucide-react'

interface Props {
  title?: string
  message: string
  onRetry?: () => void
  onDemoMode?: () => void
}

export function ErrorState({ title = 'API unavailable', message, onRetry, onDemoMode }: Props) {
  return (
    <div className="error-state">
      <AlertTriangle aria-hidden="true" size={28} />
      <h3>{title}</h3>
      <p>{message}</p>
      <div className="button-row">
        {onRetry ? <button type="button" onClick={onRetry}>Retry</button> : null}
        {onDemoMode ? <button type="button" onClick={onDemoMode}>Use Portfolio Demo Mode</button> : null}
      </div>
    </div>
  )
}

