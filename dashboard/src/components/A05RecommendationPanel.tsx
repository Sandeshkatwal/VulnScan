import type { A05InjectionSummary } from '../types/api'

export function A05RecommendationPanel({ summary }: { summary: A05InjectionSummary }) {
  const recommendations = summary.recommendations?.length ? summary.recommendations : [
    'Review output encoding.',
    'Review server-side input validation.',
    'Review parameterised queries.',
    'Confirm impact manually before reporting.',
  ]
  return (
    <div className="a05-recommendations">
      {recommendations.map((item) => <span key={item}>{item}</span>)}
    </div>
  )
}
