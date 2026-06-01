import type { BugIntelligenceMetrics, DateRangeOption } from '../types/api'

export const dateRangeOptions: Array<{ value: DateRangeOption; label: string }> = [
  { value: 'all-time', label: 'All time' },
  { value: 'last-7-days', label: 'Last 7 days' },
  { value: 'last-30-days', label: 'Last 30 days' },
  { value: 'last-90-days', label: 'Last 90 days' },
  { value: 'this-year', label: 'This year' },
]

export function formatRate(value: number | null | undefined): string {
  return `${Number(value || 0).toFixed(1)}%`
}

export function formatCurrencyMap(values: Record<string, number> | undefined): string {
  if (!values || Object.keys(values).length === 0) return '0'
  return Object.entries(values)
    .map(([currency, amount]) => `${currency} ${Number(amount || 0).toLocaleString()}`)
    .join(', ')
}

export function maxMetric(values: number[]): number {
  return Math.max(1, ...values.map((value) => Number(value || 0)))
}

export const demoBugIntelligenceMetrics: BugIntelligenceMetrics = {
  enabled: true,
  generated_at: 'demo-local',
  date_range: { range: 'all-time', start_date: null, end_date: null },
  total_evidence_records: 12,
  total_reports_created: 7,
  total_submissions: 5,
  total_accepted: 2,
  total_duplicates: 1,
  total_informative: 1,
  total_not_applicable: 0,
  total_resolved: 1,
  total_paid: 1,
  total_retests: 2,
  retest_passed_count: 1,
  retest_failed_count: 0,
  acceptance_rate: 40,
  duplicate_rate: 20,
  informative_rate: 20,
  resolution_rate: 20,
  average_time_to_report_hours: 8,
  average_time_to_triage_days: 2.5,
  average_time_to_resolution_days: 6,
  average_time_to_payment_days: 9,
  total_bounty_by_currency: { USD: 250 },
  average_bounty_by_currency: { USD: 250 },
  top_programs: [
    {
      program_name: 'Demo Program',
      total_submissions: 5,
      accepted: 2,
      duplicates: 1,
      informative: 1,
      not_applicable: 0,
      resolved: 1,
      paid: 1,
      acceptance_rate: 40,
      duplicate_rate: 20,
      total_bounty_by_currency: { USD: 250 },
      average_time_to_triage_days: 2.5,
      last_activity: 'demo-local',
    },
  ],
  top_vulnerability_classes: [
    { class_name: 'IDOR', count: 3, accepted_count: 2, duplicate_count: 0, acceptance_rate: 66.7, average_severity: 4 },
    { class_name: 'Security Misconfiguration', count: 2, accepted_count: 0, duplicate_count: 1, acceptance_rate: 0, average_severity: 3 },
  ],
  top_owasp_categories: [{ category: 'A01: Broken Access Control', count: 3 }],
  monthly_activity: [
    { month: '2026-03', evidence_created: 3, reports_created: 2, submissions_created: 1, accepted: 0, duplicates: 0, resolved: 0, paid: 0, retests_completed: 0 },
    { month: '2026-04', evidence_created: 4, reports_created: 2, submissions_created: 2, accepted: 1, duplicates: 1, resolved: 0, paid: 0, retests_completed: 0 },
    { month: '2026-05', evidence_created: 5, reports_created: 3, submissions_created: 2, accepted: 1, duplicates: 0, resolved: 1, paid: 1, retests_completed: 1 },
  ],
  outcome_distribution: [
    { outcome: 'draft', count: 0 },
    { outcome: 'submitted', count: 0 },
    { outcome: 'triaged', count: 0 },
    { outcome: 'accepted', count: 1 },
    { outcome: 'duplicate', count: 1 },
    { outcome: 'informative', count: 1 },
    { outcome: 'not_applicable', count: 0 },
    { outcome: 'resolved', count: 1 },
    { outcome: 'paid', count: 1 },
    { outcome: 'closed', count: 0 },
  ],
  quality_indicators: {
    score: 72,
    label: 'Strong Workflow',
    reasons: [
      'Demo data includes linked evidence, accepted outcomes, and one passed retest.',
      'Duplicate and informative outcomes keep the score below the highest band.',
      'Local workflow quality indicator only.',
    ],
  },
  limitations: ['Demo data only.', 'Metrics are calculated from local VulScan workflow records only.'],
}
