import type { A07AuthenticationSummary } from '../types/api'

const defaults = [
  'Review login controls manually.',
  'Review password reset flow manually.',
  'Review session cookie attributes.',
  'Review remember-me behaviour.',
  'Review account lockout and rate limiting manually.',
]

export function A07RecommendationPanel({ summary }: { summary?: A07AuthenticationSummary }) {
  const recommendations = summary?.recommendations?.length ? summary.recommendations : defaults
  return <div className="a07-recommendations">{recommendations.map((item) => <span key={item}>{item}</span>)}</div>
}
