import type { A01AccessControlSummary } from '../types/api'

export function A01RecommendationPanel({ summary }: { summary: A01AccessControlSummary }) {
  const recommendations = summary.recommendations || ['Review A01 candidates using authorised test accounts and programme-approved test data.']
  const limitations = summary.limitations || ['Candidate-only analysis. Manual Validation Required.']
  return (
    <div className="a01-recommendations">
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
