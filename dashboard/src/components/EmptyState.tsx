import { Inbox } from 'lucide-react'

interface Props {
  title?: string
  description?: string
  message?: string
  action?: string
  onAction?: () => void
}

export function EmptyState({ title, description, message, action, onAction }: Props) {
  return (
    <div className="empty-state">
      <Inbox aria-hidden="true" size={28} />
      <h3>{title || 'Empty State'}</h3>
      <p>{description || message || 'No data is available yet.'}</p>
      {action && onAction ? <button type="button" onClick={onAction}>{action}</button> : null}
    </div>
  )
}
