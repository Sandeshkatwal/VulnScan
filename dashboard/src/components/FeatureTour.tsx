import type { ApiRecord } from '../types/api'

interface Props {
  steps: ApiRecord[]
}

export function FeatureTour({ steps }: Props) {
  return (
    <div className="feature-tour">
      {steps.map((step, index) => (
        <article key={`${step.title}-${index}`} className="tour-step">
          <span>{index + 1}</span>
          <h3>{String(step.title || 'Tour step')}</h3>
          <p>{String(step.explanation || '')}</p>
          <small>{String(step.module || '')} · {String(step.safe_note || '')}</small>
        </article>
      ))}
    </div>
  )
}

