import { useEffect, useMemo, useState } from 'react'
import { getBugIntelligenceMetrics } from '../api/client'
import type { BugIntelligenceMetrics, DateRangeOption } from '../types/api'
import { dateRangeOptions, demoBugIntelligenceMetrics, formatCurrencyMap, formatRate, maxMetric } from '../utils/metrics'
import { ErrorAlert } from './ErrorAlert'

interface BugIntelligenceMetricsViewProps {
  apiOnline: boolean
  demoMode?: boolean
}

export function BugIntelligenceMetricsView({ apiOnline, demoMode = false }: BugIntelligenceMetricsViewProps) {
  const [range, setRange] = useState<DateRangeOption>('all-time')
  const [metrics, setMetrics] = useState<BugIntelligenceMetrics | null>(demoMode ? demoBugIntelligenceMetrics : null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (demoMode) {
      setMetrics({ ...demoBugIntelligenceMetrics, date_range: { ...demoBugIntelligenceMetrics.date_range, range } })
      return
    }
    if (!apiOnline) return
    setLoading(true)
    setError(null)
    getBugIntelligenceMetrics({ range })
      .then((response) => setMetrics(response.bug_intelligence_metrics))
      .catch((err) => setError(err instanceof Error ? err.message : 'Metrics could not be loaded.'))
      .finally(() => setLoading(false))
  }, [apiOnline, demoMode, range])

  const activityMax = useMemo(() => maxMetric((metrics?.monthly_activity || []).flatMap((point) => [point.reports_created, point.submissions_created, point.accepted, point.resolved])), [metrics])
  const classMax = useMemo(() => maxMetric((metrics?.top_vulnerability_classes || []).map((item) => item.count)), [metrics])
  const outcomeMax = useMemo(() => maxMetric((metrics?.outcome_distribution || []).map((item) => item.count)), [metrics])

  if (!metrics && !apiOnline && !demoMode) {
    return <div className="empty-state">API offline. Performance Metrics will load when the local API is reachable.</div>
  }

  if (!metrics) {
    return <div className="empty-state">{loading ? 'Loading Performance Metrics...' : 'No local Bug Intelligence Metrics available yet.'}</div>
  }

  return (
    <section className="metrics-view">
      <article className="workflow-safety">
        <strong>Performance Metrics use local VulScan data only.</strong>
        <span> No external platform access, browser scraping, credentials, API tokens, or automatic submissions are used.</span>
        {demoMode ? <em> Demo data only.</em> : null}
      </article>
      <ErrorAlert message={error} />

      <div className="metrics-toolbar">
        <label>
          <span>Date range</span>
          <select value={range} onChange={(event) => setRange(event.target.value as DateRangeOption)}>
            {dateRangeOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
          </select>
        </label>
        <small>{loading ? 'Refreshing...' : `Generated ${metrics.generated_at || 'locally'}`}</small>
      </div>

      <div className="metrics-card-grid">
        <MetricCard label="Evidence records" value={metrics.total_evidence_records} />
        <MetricCard label="Reports created" value={metrics.total_reports_created} />
        <MetricCard label="Submissions" value={metrics.total_submissions} />
        <MetricCard label="Accepted" value={metrics.total_accepted} />
        <MetricCard label="Duplicates" value={metrics.total_duplicates} />
        <MetricCard label="Resolved" value={metrics.total_resolved} />
        <MetricCard label="Retests passed" value={metrics.retest_passed_count} />
        <MetricCard label="Total bounty" value={formatCurrencyMap(metrics.total_bounty_by_currency)} />
        <MetricCard label="Acceptance rate" value={formatRate(metrics.acceptance_rate)} />
        <MetricCard label="Duplicate rate" value={formatRate(metrics.duplicate_rate)} />
        <MetricCard label="Quality score" value={`${metrics.quality_indicators.score}`} detail={metrics.quality_indicators.label} />
      </div>

      <div className="metrics-two-column">
        <article className="metrics-panel">
          <div className="panel-heading"><h2>Activity Trend</h2><p>Reports, submissions, accepted, and resolved by month.</p></div>
          <div className="metrics-bars metrics-bars--activity">
            {metrics.monthly_activity.map((point) => (
              <div className="metrics-month-row" key={point.month}>
                <span>{point.month}</span>
                <Bar label="Reports" value={point.reports_created} max={activityMax} tone="blue" />
                <Bar label="Submissions" value={point.submissions_created} max={activityMax} tone="green" />
                <Bar label="Accepted" value={point.accepted} max={activityMax} tone="teal" />
                <Bar label="Resolved" value={point.resolved} max={activityMax} tone="purple" />
              </div>
            ))}
          </div>
        </article>

        <article className="metrics-panel">
          <div className="panel-heading"><h2>Outcome Distribution</h2><p>Current local submission statuses.</p></div>
          <div className="metrics-bars">
            {metrics.outcome_distribution.map((item) => (
              <Bar key={item.outcome} label={item.outcome.replace('_', ' ')} value={item.count} max={outcomeMax} tone="green" />
            ))}
          </div>
        </article>
      </div>

      <article className="metrics-panel">
        <div className="panel-heading"><h2>Program Performance</h2><p>Acceptance, duplicates, bounty, and last activity per Program Scope.</p></div>
        <div className="metrics-table-wrap">
          <table className="metrics-table">
            <thead><tr><th>Program</th><th>Submissions</th><th>Accepted</th><th>Duplicates</th><th>Acceptance</th><th>Bounty</th><th>Last activity</th></tr></thead>
            <tbody>
              {metrics.top_programs.map((program) => (
                <tr key={program.program_name}>
                  <td>{program.program_name}</td>
                  <td>{program.total_submissions}</td>
                  <td>{program.accepted}</td>
                  <td>{program.duplicates}</td>
                  <td>{formatRate(program.acceptance_rate)}</td>
                  <td>{formatCurrencyMap(program.total_bounty_by_currency)}</td>
                  <td>{program.last_activity || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </article>

      <div className="metrics-two-column">
        <article className="metrics-panel">
          <div className="panel-heading"><h2>Vulnerability Classes</h2><p>Top classes with accepted and duplicate counts.</p></div>
          <div className="metrics-bars">
            {metrics.top_vulnerability_classes.map((item) => (
              <div key={item.class_name} className="metrics-class-row">
                <Bar label={item.class_name} value={item.count} max={classMax} tone="blue" />
                <small>{item.accepted_count} accepted / {item.duplicate_count} duplicate</small>
              </div>
            ))}
          </div>
        </article>

        <article className="metrics-panel metrics-quality">
          <div className="panel-heading"><h2>Quality Indicators</h2><p>Local workflow quality indicator only.</p></div>
          <div className="metrics-quality-score"><strong>{metrics.quality_indicators.score}</strong><span>{metrics.quality_indicators.label}</span></div>
          <ul>
            {metrics.quality_indicators.reasons.map((reason) => <li key={reason}>{reason}</li>)}
          </ul>
          <div className="metrics-retest-grid">
            <MetricCard label="Retests required" value={metrics.total_retests} />
            <MetricCard label="Retest passed" value={metrics.retest_passed_count} />
            <MetricCard label="Retest failed" value={metrics.retest_failed_count} />
          </div>
        </article>
      </div>
    </section>
  )
}

function MetricCard({ label, value, detail }: { label: string; value: number | string; detail?: string }) {
  return (
    <article className="metrics-card">
      <span>{label}</span>
      <strong>{value}</strong>
      {detail ? <small>{detail}</small> : null}
    </article>
  )
}

function Bar({ label, value, max, tone }: { label: string; value: number; max: number; tone: 'blue' | 'green' | 'purple' | 'teal' }) {
  const width = `${Math.max(4, (Number(value || 0) / max) * 100)}%`
  return (
    <div className="metrics-bar-row">
      <span>{label}</span>
      <div className="metrics-bar-track"><div className={`metrics-bar-fill metrics-bar-fill--${tone}`} style={{ width }} /></div>
      <strong>{value}</strong>
    </div>
  )
}
