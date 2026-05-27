import type { Finding } from '../types/api'

export interface PrioritySummary {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  fixFirst: number
  fixSoon: number
  monitor: number
  informational: number
  available: boolean
}

interface FindingSummaryProps {
  summary: PrioritySummary
  loading?: boolean
  error?: string | null
}

export function buildPrioritySummary(findings: Finding[]): PrioritySummary {
  const summary: PrioritySummary = {
    total: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    fixFirst: 0,
    fixSoon: 0,
    monitor: 0,
    informational: 0,
    available: findings.length > 0,
  }

  for (const finding of findings) {
    const label = String(finding.priority_label || '').trim()
    const severity = String(finding.severity || '').trim()
    if (severity === 'Critical') {
      summary.critical += 1
    } else if (severity === 'High') {
      summary.high += 1
    } else if (severity === 'Medium') {
      summary.medium += 1
    } else if (severity === 'Low') {
      summary.low += 1
    }

    if (label === 'Fix First') {
      summary.fixFirst += 1
    } else if (label === 'Fix Soon' || label === 'Schedule') {
      summary.fixSoon += 1
    } else if (label === 'Informational' || severity === 'Informational') {
      summary.informational += 1
    } else {
      summary.monitor += 1
    }
  }

  return summary
}

export function FindingSummary({ summary, loading = false, error }: FindingSummaryProps) {
  if (loading) {
    return <div className="panel-message">Loading finding summary...</div>
  }

  if (error) {
    return <div className="panel-message panel-message--error">{error}</div>
  }

  if (!summary.available) {
    return (
      <div className="empty-state">
        Run a scan with --prioritise or --fix-first-dashboard to populate this section.
      </div>
    )
  }

  return (
    <div className="finding-summary">
      <div>
        <span>Total Findings</span>
        <strong>{summary.total}</strong>
      </div>
      <div>
        <span>Critical</span>
        <strong>{summary.critical}</strong>
      </div>
      <div>
        <span>High</span>
        <strong>{summary.high}</strong>
      </div>
      <div>
        <span>Medium</span>
        <strong>{summary.medium}</strong>
      </div>
      <div>
        <span>Low</span>
        <strong>{summary.low}</strong>
      </div>
      <div>
        <span>Fix First</span>
        <strong>{summary.fixFirst}</strong>
      </div>
      <div>
        <span>Fix Soon</span>
        <strong>{summary.fixSoon}</strong>
      </div>
      <div>
        <span>Monitor</span>
        <strong>{summary.monitor}</strong>
      </div>
      <div>
        <span>Informational</span>
        <strong>{summary.informational}</strong>
      </div>
    </div>
  )
}
