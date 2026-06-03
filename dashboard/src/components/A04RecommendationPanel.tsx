import type { A04CryptoSummary } from '../types/api'

const defaults = [
  'Enforce HTTPS and redirect HTTP to HTTPS.',
  'Configure HSTS after HTTPS readiness review.',
  'Set Secure, HttpOnly, and SameSite cookies appropriately.',
  'Avoid sensitive data over HTTP.',
  'Remove mixed content indicators.',
  'Monitor certificate expiry.',
]

export function A04RecommendationPanel({ summary }: { summary?: A04CryptoSummary }) {
  const recommendations = summary?.recommendations?.length ? summary.recommendations : defaults
  return (
    <div className="a04-recommendations">
      {recommendations.map((item) => <span key={item}>{item}</span>)}
    </div>
  )
}
