import type { ApiRecord, Finding, JobResultResponse, JobSummary } from '../types/api'
import {
  countByPriority,
  countBySeverity,
  countBySource,
  countCveFindings,
  countExploitMetadata,
  getHighestPriorityScore,
  getHighestRiskScore,
  getTopRiskFindings,
} from '../utils/riskMetrics'
import { AssetContextCard } from './AssetContextCard'
import { DistributionChart } from './DistributionChart'
import { ErrorAlert } from './ErrorAlert'
import { LoadingSpinner } from './LoadingSpinner'
import { RiskMetricCard } from './RiskMetricCard'
import { TopRiskFindings } from './TopRiskFindings'
import { TrendSummaryCard } from './TrendSummaryCard'

interface RiskOverviewProps {
  job?: JobSummary | null
  result?: JobResultResponse | null
  findings: Finding[]
  loading?: boolean
  error?: string | null
  apiOnline?: boolean
  onSelectFinding: (finding: Finding) => void
}

function resultPayload(result?: JobResultResponse | null): ApiRecord {
  return (result?.result && typeof result.result === 'object' ? result.result : {}) as ApiRecord
}

function assetCriticality(result: ApiRecord, findings: Finding[]): unknown {
  const context = result.asset_context as ApiRecord | undefined
  const summary = result.prioritisation_summary as ApiRecord | undefined
  return context?.criticality ?? summary?.asset_criticality ?? findings.find((finding) => finding.asset_criticality)?.asset_criticality
}

export function RiskOverview({
  job,
  result,
  findings,
  loading = false,
  error,
  apiOnline = true,
  onSelectFinding,
}: RiskOverviewProps) {
  if (!apiOnline) {
    return <div className="empty-state">API offline. Risk overview will load when the local API is reachable.</div>
  }

  if (!job?.job_id) {
    return <div className="empty-state">Run or select a completed scan to view risk overview.</div>
  }

  if (job.status !== 'completed') {
    return <div className="empty-state">Select a completed job to view risk overview.</div>
  }

  if (loading) {
    return (
      <div className="panel-message">
        <LoadingSpinner label="Loading risk overview" />
      </div>
    )
  }

  if (findings.length === 0 && !error) {
    return <div className="empty-state">No findings available for this job.</div>
  }

  const payload = resultPayload(result)
  const severityCounts = countBySeverity(findings)
  const priorityCounts = countByPriority(findings)
  const sourceCounts = countBySource(findings)
  const fixFirst = priorityCounts['Fix First']
  const criticalHigh = severityCounts.Critical + severityCounts.High
  const topFindings = getTopRiskFindings(findings, 5)
  const trends = payload.prioritisation_trends as ApiRecord | undefined
  const dashboard = payload.fix_first_dashboard as ApiRecord | undefined
  const context = payload.asset_context as ApiRecord | undefined

  return (
    <div className="risk-overview">
      <ErrorAlert message={error} />
      <div className="risk-metric-grid">
        <RiskMetricCard label="Total Findings" value={findings.length} />
        <RiskMetricCard label="Critical/High Findings" value={criticalHigh} />
        <RiskMetricCard label="Fix First Findings" value={fixFirst} />
        <RiskMetricCard label="Highest Priority Score" value={getHighestPriorityScore(findings)} />
        <RiskMetricCard label="Highest Risk Score" value={getHighestRiskScore(findings)} />
        <RiskMetricCard label="Exploit Metadata Available Count" value={countExploitMetadata(findings)} />
        <RiskMetricCard label="CVE Findings Count" value={countCveFindings(findings)} />
        <RiskMetricCard label="Asset Criticality" value={assetCriticality(payload, findings)} />
      </div>

      <div className="risk-chart-grid">
        <DistributionChart title="Severity Distribution" data={severityCounts} />
        <DistributionChart title="Priority Distribution" data={priorityCounts} />
        <DistributionChart title="Source Distribution" data={sourceCounts} />
      </div>

      <div className="risk-context-grid">
        <section className="context-card">
          <h3>Top Risk Findings</h3>
          <TopRiskFindings findings={topFindings} onSelectFinding={onSelectFinding} />
        </section>
        <section className="context-card">
          <h3>Trend Summary</h3>
          <TrendSummaryCard trends={trends} dashboard={dashboard} />
        </section>
        <section className="context-card">
          <h3>Asset Context</h3>
          <AssetContextCard assetContext={context} job={job} findings={findings} />
        </section>
      </div>
    </div>
  )
}
