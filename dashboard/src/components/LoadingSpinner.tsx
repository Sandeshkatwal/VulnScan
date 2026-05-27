interface LoadingSpinnerProps {
  label?: string
}

export function LoadingSpinner({ label = 'Loading' }: LoadingSpinnerProps) {
  return (
    <span className="loading-spinner" role="status">
      <span aria-hidden="true" />
      {label}
    </span>
  )
}
