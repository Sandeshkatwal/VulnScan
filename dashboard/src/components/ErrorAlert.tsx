interface ErrorAlertProps {
  message?: string | null
}

export function ErrorAlert({ message }: ErrorAlertProps) {
  if (!message) return null

  return (
    <div className="error-alert" role="alert">
      {message}
    </div>
  )
}
