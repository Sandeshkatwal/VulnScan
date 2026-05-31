import type { OWASPCategory, OWASPSummary } from '../types/api'

interface OWASPCategoryTableProps {
  categories: OWASPCategory[]
  summary?: OWASPSummary
}

export function OWASPCategoryTable({ categories, summary }: OWASPCategoryTableProps) {
  const counts = summary?.category_counts || {}
  const confidence = summary?.category_confidence_counts || {}
  return (
    <div className="table-shell">
      <table>
        <thead>
          <tr>
            <th>Category</th>
            <th>Count</th>
            <th>Confidence</th>
            <th>Status</th>
            <th>Mapped examples</th>
          </tr>
        </thead>
        <tbody>
          {categories.map((category) => {
            const count = counts[category.owasp_id || ''] || 0
            const confidenceCounts = confidence[category.owasp_id || ''] || {}
            return (
              <tr key={category.owasp_id}>
                <td>{category.owasp_id} {category.name}</td>
                <td>{count}</td>
                <td>H {confidenceCounts.High || 0} / M {confidenceCounts.Medium || 0} / L {confidenceCounts.Low || 0}</td>
                <td>{count > 0 ? 'Detected indicators' : summary?.enabled ? 'No indicators' : 'Not assessed'}</td>
                <td>{category.short_description}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
