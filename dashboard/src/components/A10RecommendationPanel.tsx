import type { A10ErrorHandlingSummary } from '../types/api'

const fallback = [
  'Disable detailed errors in production.',
  'Return generic user-facing error messages.',
  'Log diagnostic detail safely server-side.',
  'Review sensitive workflows for fail-safe behaviour.',
]

export function A10RecommendationPanel({ summary }: { summary?: A10ErrorHandlingSummary }) {
  const recommendations = summary?.recommendations?.length ? summary.recommendations : fallback
  return (
    <div className="a10-recommendations">
      {recommendations.map((recommendation) => <span key={recommendation}>{recommendation}</span>)}
    </div>
  )
}
