export type ApiRecord = Record<string, unknown>

export interface Pagination {
  limit?: number
  offset?: number
  returned?: number
  total?: number
  has_next?: boolean
  has_previous?: boolean
  next_offset?: number | null
  previous_offset?: number | null
  [key: string]: unknown
}

export interface ApiError {
  error?: string
  detail?: string
  message?: string
  status?: number
  [key: string]: unknown
}

export interface HealthResponse {
  status?: string
  scanner?: string
  [key: string]: unknown
}

export interface VersionResponse {
  scanner?: string
  version?: string
  api_version?: string
  [key: string]: unknown
}

export interface JobSummary {
  job_id?: string
  scan_id?: string
  target?: string
  status?: string
  created_at?: string
  started_at?: string
  completed_at?: string
  duration_seconds?: number | null
  result_summary?: ApiRecord
  result_path?: string | null
  result_download_url?: string | null
  html_report_path?: string | null
  html_view_url?: string | null
  html_download_url?: string | null
  error_message?: string | null
  safe_error_code?: string | null
  [key: string]: unknown
}

export type JobDetail = JobSummary

export interface JobsResponse {
  jobs: JobSummary[]
  pagination?: Pagination | null
  filters?: ApiRecord | null
  [key: string]: unknown
}

export interface ScanSummary {
  scan_id?: string
  target?: string
  host?: string
  scan_time?: string
  scan_start_time?: string
  created_at?: string
  duration_seconds?: number | null
  findings_count?: number | null
  finding_count?: number | null
  total_findings?: number | null
  [key: string]: unknown
}

export interface ScansResponse {
  scans: ScanSummary[]
  pagination?: Pagination | null
  filters?: ApiRecord | null
  [key: string]: unknown
}

export interface Finding {
  id?: string
  finding_id?: string
  title?: string
  severity?: string
  source?: string
  category?: string
  description?: string
  evidence?: string
  evidence_details?: ApiRecord
  impact?: string
  risk_score?: number | null
  risk_label?: string
  priority_score?: number | null
  priority_label?: string
  priority_reasons?: string[]
  recommendation?: string
  recommended_action?: string
  verification?: string
  limitation?: string
  sla_hint?: string
  cve?: string
  cvss_score?: number | string | null
  cvss_vector?: string
  epss_score?: number | string | null
  epss_percentile?: number | string | null
  exploit_available?: boolean | string | null
  exploit_maturity?: string
  active_exploitation_reported?: boolean | string | null
  affected_urls?: string[]
  affected_url?: string
  affected_host?: string
  asset_criticality?: string
  asset_environment?: string
  asset_business_owner?: string
  asset_tags?: string[]
  remediation_status?: string
  fix_first_rank?: number | null
  [key: string]: unknown
}

export interface PrioritisationTrends {
  enabled?: boolean
  status?: string
  target?: string
  previous_scan_id?: string | null
  previous_scan_time?: string | null
  current_scan_time?: string | null
  previous_findings_count?: number | null
  current_findings_count?: number | null
  new_findings_count?: number | null
  resolved_findings_count?: number | null
  unchanged_findings_count?: number | null
  priority_increased_count?: number | null
  priority_decreased_count?: number | null
  priority_label_changed_count?: number | null
  fix_first_new_count?: number | null
  fix_first_resolved_count?: number | null
  fix_first_persisting_count?: number | null
  previous_average_priority_score?: number | null
  current_average_priority_score?: number | null
  average_priority_delta?: number | null
  previous_highest_priority_score?: number | null
  current_highest_priority_score?: number | null
  highest_priority_delta?: number | null
  risk_trend_label?: string
  trend_limitations?: string[]
  [key: string]: unknown
}

export interface TrendDetailItem {
  stable_key?: string
  title?: string
  source?: string
  category?: string
  previous_priority_score?: number | null
  current_priority_score?: number | null
  previous_priority_label?: string
  current_priority_label?: string
  score_delta?: number | null
  trend_status?: string
  reason_summary?: string
  [key: string]: unknown
}

export interface PrioritisationTrendDetails {
  new_findings?: TrendDetailItem[]
  resolved_findings?: TrendDetailItem[]
  priority_increased?: TrendDetailItem[]
  priority_decreased?: TrendDetailItem[]
  fix_first_new?: TrendDetailItem[]
  fix_first_resolved?: TrendDetailItem[]
  fix_first_persisting?: TrendDetailItem[]
  [key: string]: unknown
}

export interface FindingsResponse {
  findings: Finding[]
  pagination?: Pagination | null
  filters?: ApiRecord | null
  message?: string
  [key: string]: unknown
}

export interface ScanResponse {
  job_id?: string
  scan_id?: string
  status?: string
  target?: string
  summary?: ApiRecord
  result_path?: string | null
  html_report_path?: string | null
  retrievable?: boolean
  status_url?: string | null
  result_url?: string | null
  [key: string]: unknown
}

export interface JobResultResponse {
  job_id?: string
  status?: string
  job?: JobSummary
  result?: ApiRecord | null
  message?: string
  [key: string]: unknown
}

export interface ReportSummary {
  job_id?: string
  scan_id?: string
  target?: string
  status?: string
  result_path?: string | null
  result_download_url?: string | null
  html_report_path?: string | null
  html_view_url?: string | null
  html_download_url?: string | null
  completed_at?: string
  duration_seconds?: number | null
  findings_count?: number | null
  has_json_report?: boolean
  has_html_report?: boolean
  has_fix_first_dashboard?: boolean
  has_trend_data?: boolean
  has_vuln_intel?: boolean
  has_web_dast?: boolean
  [key: string]: unknown
}

export interface ReportFileSummary {
  report_id?: string
  filename?: string
  type?: 'json' | 'html' | string
  target?: string
  created_at?: string
  size_bytes?: number | null
  download_url?: string | null
  view_url?: string | null
  [key: string]: unknown
}

export interface ReportsQuery {
  limit?: number
  offset?: number
  type?: 'json' | 'html' | 'all'
  target?: string
}

export interface ReportsResponse {
  reports: ReportFileSummary[]
  pagination?: Pagination | null
  filters?: ApiRecord | null
  [key: string]: unknown
}

export interface ReportMetadataResponse {
  report?: ReportFileSummary
  [key: string]: unknown
}

export interface ReportMetadata {
  report_summary?: ReportSummary
  prioritisation_summary?: ApiRecord | null
  fix_first_dashboard?: ApiRecord | null
  prioritisation_trends?: ApiRecord | null
  vulnerability_intelligence?: ApiRecord | null
  web_dast_summary?: ApiRecord | null
  asset_context?: ApiRecord | null
  [key: string]: unknown
}

export interface ScanRequest {
  target: string
  scan_mode?: 'safe'
  json_report?: boolean
  html_report?: boolean
  save_db?: boolean
  vuln_intel?: boolean
  prioritise?: boolean
  fix_first_dashboard?: boolean
}

export interface JobsQuery {
  limit?: number
  offset?: number
  status?: string
  target?: string
  sort_by?: string
  sort_order?: string
}

export interface ScansQuery {
  limit?: number
  offset?: number
  target?: string
  sort_by?: string
  sort_order?: string
}

export interface FindingFilters {
  severity?: string
  source?: string
  category?: string
  priority_label?: string
  min_priority_score?: string
  min_risk_score?: string
  compact?: boolean
  limit?: number
  offset?: number
  sort_by?: string
  sort_order?: string
}
