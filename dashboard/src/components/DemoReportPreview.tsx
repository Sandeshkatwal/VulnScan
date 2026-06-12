import type { DemoDataset } from '../types/api'

interface Props {
  dataset: DemoDataset
}

export function DemoReportPreview({ dataset }: Props) {
  const summary = dataset.dashboard_summary || {}
  return (
    <div className="demo-report-preview">
      <h3>Demo Report</h3>
      <p>{dataset.safe_testing_statement}</p>
      <div className="mini-metrics">
        <span>Findings: {summary.findings || 0}</span>
        <span>OWASP Categories: {summary.owasp_categories_covered || 0}</span>
        <span>Evidence Items: {summary.evidence_items || 0}</span>
      </div>
    </div>
  )
}

