interface Props {
  message?: string
}

export function LoadingState({ message = 'Loading dashboard data...' }: Props) {
  return (
    <div className="loading-state">
      <div className="skeleton-card" />
      <div>
        <strong>{message}</strong>
        <p>Preparing local dashboard context.</p>
      </div>
    </div>
  )
}

