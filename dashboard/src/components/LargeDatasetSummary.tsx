interface Props {
  findings?: number
  evidence?: number
  reports?: number
  manualPlans?: number
}

export function LargeDatasetSummary({ findings = 0, evidence = 0, reports = 0, manualPlans = 0 }: Props) {
  return (
    <div className="large-dataset-summary">
      <Metric label="Findings" value={findings} />
      <Metric label="Evidence" value={evidence} />
      <Metric label="Reports" value={reports} />
      <Metric label="Manual Plans" value={manualPlans} />
    </div>
  )
}

function Metric({ label, value }: { label: string; value: number }) {
  return <div><span>{label}</span><strong>{value}</strong></div>
}
