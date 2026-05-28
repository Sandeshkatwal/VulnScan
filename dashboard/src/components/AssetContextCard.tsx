import type { ApiRecord, Finding, JobSummary } from '../types/api'
import { formatValue } from '../utils/format'

interface AssetContextCardProps {
  assetContext?: ApiRecord | null
  job?: JobSummary | null
  findings: Finding[]
}

function firstAvailable(...values: unknown[]): unknown {
  return values.find((value) => value !== undefined && value !== null && value !== '')
}

export function AssetContextCard({ assetContext, job, findings }: AssetContextCardProps) {
  const findingWithAsset = findings.find((finding) => finding.asset_criticality || finding.asset_environment || finding.asset_business_owner)
  const enabled = assetContext?.enabled === true || Boolean(findingWithAsset?.asset_criticality)

  if (!enabled) {
    return <div className="context-card__message">Asset context is available when scans use asset criticality.</div>
  }

  const rows: Array<[string, unknown]> = [
    ['Target', firstAvailable(assetContext?.target, job?.target, findingWithAsset?.affected_host)],
    ['Criticality', firstAvailable(assetContext?.criticality, findingWithAsset?.asset_criticality)],
    ['Environment', firstAvailable(assetContext?.environment, findingWithAsset?.asset_environment)],
    ['Business owner', firstAvailable(assetContext?.business_owner, findingWithAsset?.asset_business_owner)],
    ['Tags', firstAvailable(assetContext?.tags, findingWithAsset?.asset_tags)],
  ]

  return (
    <dl className="context-card__grid">
      {rows.map(([label, value]) => (
        <div key={String(label)}>
          <dt>{String(label)}</dt>
          <dd>{formatValue(value)}</dd>
        </div>
      ))}
    </dl>
  )
}
