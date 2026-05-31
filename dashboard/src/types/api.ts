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
  finding_key?: string
  remediation_fingerprint?: string
  remediation_fingerprint_short?: string
  remediation_status?: string
  remediation_owner?: string | null
  remediation_due_date?: string | null
  remediation_note?: string | null
  remediation_updated_at?: string | null
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

export type RemediationStatus = 'open' | 'in_progress' | 'fixed' | 'accepted_risk' | 'false_positive'

export interface RemediationRecord {
  finding_key?: string
  finding_key_short?: string
  finding_id?: string | null
  target?: string | null
  title?: string | null
  source?: string | null
  category?: string | null
  severity?: string | null
  priority_label?: string | null
  status?: RemediationStatus | string
  owner?: string | null
  due_date?: string | null
  note?: string | null
  first_seen?: string | null
  last_seen?: string | null
  created_at?: string | null
  updated_at?: string | null
  history?: RemediationHistoryItem[]
  [key: string]: unknown
}

export interface RemediationHistoryItem {
  old_status?: RemediationStatus | string
  new_status?: RemediationStatus | string
  note?: string | null
  updated_at?: string | null
}

export interface RemediationSummary {
  open_count?: number
  in_progress_count?: number
  fixed_count?: number
  accepted_risk_count?: number
  false_positive_count?: number
  overdue_count?: number
  total_count?: number
  [key: string]: unknown
}

export interface RemediationQuery {
  target?: string
  status?: RemediationStatus | string
  severity?: string
  source?: string
  priority_label?: string
  limit?: number
  offset?: number
}

export interface RemediationResponse {
  records: RemediationRecord[]
  pagination?: Pagination | null
  filters?: ApiRecord | null
  [key: string]: unknown
}

export interface RemediationRecordResponse {
  record?: RemediationRecord
  [key: string]: unknown
}

export interface RemediationUpdatePayload {
  status: RemediationStatus
  note?: string
  owner?: string
  due_date?: string
}

export interface RemediationUpdateResponse {
  finding_key?: string
  status?: RemediationStatus | string
  updated_at?: string
  note?: string | null
  record?: RemediationRecord
  [key: string]: unknown
}

export interface BugBountyScopeSummary {
  program_id?: string
  program_name?: string
  platform?: string
  policy_url?: string
  scope_version?: string
  last_updated?: string
  scope_file?: string
  in_scope_domain_count?: number
  out_of_scope_domain_count?: number
  [key: string]: unknown
}

export interface BugBountyScopeRules {
  domains?: string[]
  urls?: string[]
  api_base_urls?: string[]
  ip_ranges?: string[]
  [key: string]: unknown
}

export interface BugBountyScopeDetail {
  metadata?: BugBountyScopeSummary
  scope?: {
    program_id?: string
    program_name?: string
    platform?: string
    policy_url?: string
    scope_version?: string
    last_updated?: string
    safe_testing_notice?: string
    in_scope?: BugBountyScopeRules
    out_of_scope?: BugBountyScopeRules
    forbidden_actions?: string[]
    allowed_test_types?: string[]
    disallowed_test_types?: string[]
    rate_limits?: ApiRecord
    notes?: string[]
    [key: string]: unknown
  }
  [key: string]: unknown
}

export interface BugBountyScopesResponse {
  scopes: BugBountyScopeSummary[]
  [key: string]: unknown
}

export interface ScopeDecision {
  target?: string
  in_scope?: boolean
  reason?: string
  matched_rule?: string
  program_id?: string
  program_name?: string
  [key: string]: unknown
}

export interface ScopeCheckRequest {
  target: string
  scope_file: string
}

export type ScopeCheckResponse = ScopeDecision

export interface ReconTechnologyHint {
  name?: string
  source?: string
  confidence?: string
  [key: string]: unknown
}

export interface ReconSecurityHeaderPresence {
  hsts_present?: boolean
  csp_present?: boolean
  x_frame_options_present?: boolean
  x_content_type_options_present?: boolean
  [key: string]: unknown
}

export interface BugBountyReconSummary {
  enabled?: boolean
  program_id?: string
  program_name?: string
  input_source?: string
  input_targets_count?: number
  normalised_targets_count?: number
  in_scope_targets_count?: number
  out_of_scope_targets_count?: number
  probe_candidates_count?: number
  probed_count?: number
  live_count?: number
  error_count?: number
  skipped_count?: number
  technologies_observed?: string[]
  status_code_distribution?: ApiRecord
  content_type_distribution?: ApiRecord
  limitations?: string[]
  [key: string]: unknown
}

export interface BugBountyReconResult {
  target?: string
  target_type?: string
  probe_url?: string
  final_url?: string
  status_code?: number | null
  live?: boolean
  page_title?: string
  server_header?: string
  x_powered_by?: string
  content_type?: string
  content_length?: number | null
  redirect_chain?: string[]
  response_time_ms?: number
  in_scope?: boolean
  scope_reason?: string
  technology_hints?: ReconTechnologyHint[]
  security_header_presence?: ReconSecurityHeaderPresence
  error_code?: string
  error_message?: string
  [key: string]: unknown
}

export interface BugBountyReconSkipped {
  target?: string
  probe_url?: string
  reason?: string
  scope_reason?: string
  matched_rule?: string
  [key: string]: unknown
}

export interface BugBountyReconRequest {
  targets: string[]
  scope_file?: string
  enforce_scope?: boolean
  request_delay?: number
  max_requests_per_minute?: number
  timeout?: number
  max_redirects?: number
}

export interface BugBountyReconResponse {
  bug_bounty_recon?: BugBountyReconSummary
  bug_bounty_recon_results?: BugBountyReconResult[]
  bug_bounty_recon_skipped?: BugBountyReconSkipped[]
  findings?: Finding[]
  [key: string]: unknown
}

export interface BugBountyReconReportSummary {
  recon_id?: string
  path?: string
  created_at?: string
  program_id?: string
  program_name?: string
  input_targets_count?: number
  live_count?: number
  skipped_count?: number
  [key: string]: unknown
}

export interface BugBountyReconReportsResponse {
  reports: BugBountyReconReportSummary[]
  [key: string]: unknown
}
