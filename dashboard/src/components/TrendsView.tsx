import type { JobResultResponse, JobSummary } from '../types/api'
import { formatSignedNumber, formatValue } from '../utils/format'
import {
  getFixFirstDashboard,
  getResultRecord,
  getTrendDetails,
  getTrends,
  hasTrendData,
  trendCounts,
  trendValue,
} from '../utils/trendMetrics'
import { DistributionChart } from './DistributionChart'
import { LoadingSpinner } from './LoadingSpinner'
import { TrendComparisonPanel } from './TrendComparisonPanel'
import { TrendDetailsTable } from './TrendDetailsTable'
import { TrendMetricCard } from './TrendMetricCard'

interface TrendsViewProps {
  job?: JobSummary | null
  result?: JobResultResponse | null
  resultLoading?: boolean
  resultError?: string | null
}

function hasResultPayload(result?: JobResultResponse | null): boolean {
  return Boolean(result?.result && typeof result.result === 'object')
}

function trendLimitations(trends: ReturnType<typeof getTrends>): string[] {
  return Array.isArray(trends?.trend_limitations) ? trends.trend_limitations : []
}

export function TrendsView({ job, result, resultLoading = false, resultError }: TrendsViewProps) {
  if (!job?.job_id) {
    return <div className="empty-state">Select a completed job to view trends.</div>
  }

  if (job.status !== 'completed') {
    return <div className="empty-state">Select a completed job to view trends.</div>
  }

  if (resultLoading) {
    return (
      <div className="panel-message">
        <LoadingSpinner label="Loading trend data" />
      </div>
    )
  }

  if (resultError) {
    return <div className="panel-message panel-message--error">Trend data could not be loaded.</div>
  }

  if (!hasResultPayload(result)) {
    return <div className="empty-state">Load the job result to view trend data.</div>
  }

  const payload = getResultRecord(result)
  const trends = getTrends(payload)
  const details = getTrendDetails(payload)
  const dashboard = getFixFirstDashboard(payload)

  if (!hasTrendData(trends, dashboard)) {
    return <div className="empty-state">Trend data is available when scans are run with --priority-trends and --save-db.</div>
  }

  const limitations = trendLimitations(trends)
  const isBaseline = String(trends?.status || '').toLowerCase() === 'baseline'
  const detailSections = [
    ['New Findings', details.new_findings],
    ['Resolved Findings', details.resolved_findings],
    ['Priority Increased', details.priority_increased],
    ['Priority Decreased', details.priority_decreased],
    ['New Fix First', details.fix_first_new],
    ['Resolved Fix First', details.fix_first_resolved],
    ['Persisting Fix First', details.fix_first_persisting],
  ] as const
  const hasAnyDetails = detailSections.some(([, items]) => Array.isArray(items) && items.length > 0)

  return (
    <div className="trends-view">
      {isBaseline ? <div className="info-message">This scan is the baseline for future comparisons.</div> : null}
      <div className="trend-metric-grid">
        <TrendMetricCard label="Risk Trend" value={trendValue(trends, dashboard, 'risk_trend_label')} status />
        <TrendMetricCard label="New Findings" value={trendValue(trends, dashboard, 'new_findings_count')} />
        <TrendMetricCard label="Resolved Findings" value={trendValue(trends, dashboard, 'resolved_findings_count')} />
        <TrendMetricCard label="Priority Increased" value={trendValue(trends, dashboard, 'priority_increased_count')} />
        <TrendMetricCard label="Priority Decreased" value={trendValue(trends, dashboard, 'priority_decreased_count')} />
        <TrendMetricCard label="New Fix First" value={trendValue(trends, dashboard, 'fix_first_new_count', 'new_fix_first_count')} />
        <TrendMetricCard label="Resolved Fix First" value={trendValue(trends, dashboard, 'fix_first_resolved_count', 'resolved_fix_first_count')} />
        <TrendMetricCard label="Persisting Fix First" value={trendValue(trends, dashboard, 'fix_first_persisting_count')} />
        <TrendMetricCard label="Average Priority Delta" value={trendValue(trends, dashboard, 'average_priority_delta')} signed />
        <TrendMetricCard label="Highest Priority Delta" value={trendValue(trends, dashboard, 'highest_priority_delta')} signed />
      </div>

      <div className="trend-summary-grid">
        <section className="context-card">
          <h3>Trend Counts</h3>
          <DistributionChart title="Trend Counts" data={trendCounts(trends, dashboard)} />
        </section>
        <section className="context-card">
          <h3>Comparison</h3>
          <TrendComparisonPanel trends={trends} dashboard={dashboard} />
        </section>
        <section className="context-card">
          <h3>Trend Status</h3>
          <dl className="context-card__grid">
            <div>
              <dt>Status</dt>
              <dd>{formatValue(trends?.status)}</dd>
            </div>
            <div>
              <dt>Target</dt>
              <dd>{formatValue(trends?.target)}</dd>
            </div>
            <div>
              <dt>Average delta</dt>
              <dd>{formatSignedNumber(trendValue(trends, dashboard, 'average_priority_delta'))}</dd>
            </div>
            <div>
              <dt>Limitations</dt>
              <dd>{limitations.length ? limitations.join(', ') : 'Not available'}</dd>
            </div>
          </dl>
        </section>
      </div>

      <div className="trend-details-grid">
        {!hasAnyDetails ? <div className="empty-state">No trend details available.</div> : null}
        {detailSections.map(([title, items]) => (
          <TrendDetailsTable key={title} title={title} items={Array.isArray(items) ? items : []} />
        ))}
      </div>
    </div>
  )
}
