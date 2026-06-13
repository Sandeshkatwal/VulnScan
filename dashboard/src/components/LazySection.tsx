import { useState } from 'react'
import type { ReactNode } from 'react'

interface Props {
  title: string
  summary?: ReactNode
  defaultOpen?: boolean
  loading?: boolean
  error?: string | null
  onOpen?: () => void
  onRetry?: () => void
  children: ReactNode
}

export function LazySection({
  title,
  summary,
  defaultOpen = false,
  loading = false,
  error,
  onOpen,
  onRetry,
  children,
}: Props) {
  const [open, setOpen] = useState(defaultOpen)

  function toggle() {
    const next = !open
    setOpen(next)
    if (next) onOpen?.()
  }

  return (
    <section className="lazy-section">
      <button className="lazy-section__header" type="button" onClick={toggle} aria-expanded={open}>
        <span>{title}</span>
        <span>{open ? 'Hide' : 'Show'}</span>
      </button>
      {summary ? <div className="lazy-section__summary">{summary}</div> : null}
      {open ? (
        <div className="lazy-section__body">
          {loading ? <div className="panel-message">Loading section...</div> : null}
          {error ? (
            <div className="panel-message panel-message--error">
              <span>{error}</span>
              {onRetry ? <button className="secondary-button" type="button" onClick={onRetry}>Retry</button> : null}
            </div>
          ) : null}
          {!loading && !error ? children : null}
        </div>
      ) : null}
    </section>
  )
}
