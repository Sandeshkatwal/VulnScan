import type { ApiRecord, PrioritisationTrendDetails, PrioritisationTrends } from '../types/api'

export type TrendLabel = 'Improved' | 'Worsened' | 'Stable' | 'Baseline' | 'Unknown'

export function normaliseTrendLabel(value: unknown): TrendLabel {
  const text = String(value ?? '').trim().toLowerCase()
  if (text === 'improved') return 'Improved'
  if (text === 'worsened') return 'Worsened'
  if (text === 'stable') return 'Stable'
  if (text === 'baseline') return 'Baseline'
  return 'Unknown'
}

export function isRecord(value: unknown): value is ApiRecord {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value))
}

export function getResultRecord(result: unknown): ApiRecord {
  if (!isRecord(result)) return {}
  const payload = result.result
  return isRecord(payload) ? payload : {}
}

export function getTrends(payload: ApiRecord): PrioritisationTrends | null {
  const trends = payload.prioritisation_trends
  if (!isRecord(trends)) return null
  return trends as PrioritisationTrends
}

export function getTrendDetails(payload: ApiRecord): PrioritisationTrendDetails {
  const details = payload.prioritisation_trend_details
  return isRecord(details) ? (details as PrioritisationTrendDetails) : {}
}

export function getFixFirstDashboard(payload: ApiRecord): ApiRecord {
  const dashboard = payload.fix_first_dashboard
  return isRecord(dashboard) ? dashboard : {}
}

export function trendValue(trends: PrioritisationTrends | null, dashboard: ApiRecord, trendKey: keyof PrioritisationTrends, dashboardKey?: string): unknown {
  return trends?.[trendKey] ?? (dashboardKey ? dashboard[dashboardKey] : undefined)
}

function toCount(value: unknown): number {
  const count = Number(value ?? 0)
  return Number.isFinite(count) ? count : 0
}

export function trendCounts(trends: PrioritisationTrends | null, dashboard: ApiRecord): Record<string, number> {
  return {
    New: toCount(trendValue(trends, dashboard, 'new_findings_count')),
    Resolved: toCount(trendValue(trends, dashboard, 'resolved_findings_count')),
    Increased: toCount(trendValue(trends, dashboard, 'priority_increased_count')),
    Decreased: toCount(trendValue(trends, dashboard, 'priority_decreased_count')),
    'New Fix First': toCount(trendValue(trends, dashboard, 'fix_first_new_count', 'new_fix_first_count')),
    'Resolved Fix First': toCount(trendValue(trends, dashboard, 'fix_first_resolved_count', 'resolved_fix_first_count')),
  }
}

export function hasTrendData(trends: PrioritisationTrends | null, dashboard: ApiRecord): boolean {
  if (!trends && !Object.keys(dashboard).length) return false
  const label = trends?.risk_trend_label ?? dashboard.risk_trend_label
  return Boolean(label || trends?.status || trends?.enabled)
}
