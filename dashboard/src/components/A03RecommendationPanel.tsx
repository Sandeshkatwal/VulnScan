import type { A03SupplyChainSummary } from '../types/api'

export function A03RecommendationPanel({ summary }: { summary: A03SupplyChainSummary }) {
  const recommendations = summary.recommendations || [
    'Maintain an SBOM and review component inventory regularly.',
    'Update vulnerable components after validating component identity and version.',
    'Avoid exposing dependency metadata publicly unless intentionally published.',
    'Use SRI/CSP where appropriate for third-party scripts.',
  ]
  const limitations = summary.limitations || ['A03 checks use supplied/discovered metadata and local intelligence only.']
  return (
    <div className="recommendation-grid">
      <div>
        <h4>Recommendations</h4>
        <ul>{recommendations.map((item) => <li key={item}>{item}</li>)}</ul>
      </div>
      <div>
        <h4>Limitations</h4>
        <ul>{limitations.map((item) => <li key={item}>{item}</li>)}</ul>
      </div>
    </div>
  )
}
