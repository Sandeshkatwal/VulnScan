import { formatValue } from '../utils/format'

interface ReportCardProps {
  label: string
  value: unknown
}

export function ReportCard({ label, value }: ReportCardProps) {
  return (
    <div className="report-card">
      <span>{label}</span>
      <strong>{formatValue(value)}</strong>
    </div>
  )
}
