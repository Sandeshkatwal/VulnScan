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

export interface EndpointDiscoverySummary {
  enabled?: boolean
  program_id?: string
  program_name?: string
  input_source?: string
  input_urls_count?: number
  normalised_urls_count?: number
  deduplicated_urls_count?: number
  in_scope_urls_count?: number
  out_of_scope_urls_count?: number
  skipped_urls_count?: number
  endpoints_with_parameters_count?: number
  interesting_parameters_count?: number
  high_interest_count?: number
  medium_interest_count?: number
  low_interest_count?: number
  static_asset_count?: number
  endpoint_category_distribution?: ApiRecord
  parameter_type_distribution?: ApiRecord
  limitations?: string[]
  [key: string]: unknown
}

export interface EndpointResult {
  original_url?: string
  normalised_url?: string
  host?: string
  path?: string
  extension?: string
  parameters?: Array<{ name?: string; value_redacted?: boolean; [key: string]: unknown }>
  endpoint_category?: string
  candidate_score?: number
  candidate_label?: string
  candidate_reasons?: string[]
  in_scope?: boolean
  scope_reason?: string
  source?: string
  [key: string]: unknown
}

export interface ParameterResult {
  url?: string
  path?: string
  parameter_name?: string
  parameter_value_redacted?: boolean
  parameter_type?: string
  potential_issue?: string
  confidence?: string
  candidate_score?: number
  recommendation?: string
  manual_validation_note?: string
  [key: string]: unknown
}

export interface EndpointSkipped {
  original_url?: string
  reason?: string
  scope_reason?: string
  [key: string]: unknown
}

export interface EndpointDiscoveryRequest {
  urls: string[]
  base_url?: string
  scope_file?: string
  enforce_scope?: boolean
}

export interface EndpointDiscoveryResponse {
  endpoint_discovery?: EndpointDiscoverySummary
  endpoint_results?: EndpointResult[]
  parameter_results?: ParameterResult[]
  endpoint_skipped?: EndpointSkipped[]
  findings?: Finding[]
  [key: string]: unknown
}

export interface EndpointReportSummary {
  report_id?: string
  path?: string
  created_at?: string
  input_urls_count?: number
  high_interest_count?: number
  interesting_parameters_count?: number
  [key: string]: unknown
}

export interface EndpointReportsResponse {
  reports: EndpointReportSummary[]
  [key: string]: unknown
}

export interface SessionProfileSummary {
  profile_id?: string
  profile_name?: string
  target_base_url?: string
  auth_type?: string
  redaction_status?: string
  safe_display_name?: string
  cookies_redacted?: boolean
  headers_redacted?: boolean
  auth_headers_present?: boolean
  cookie_names?: string[]
  header_names?: string[]
  role_label?: string
  permission_notes?: string
  expiry_hint?: string
  allowed_hosts?: string[]
  allowed_paths?: string[]
  blocked_paths?: string[]
  notes?: string
  local_only?: boolean
  updated_at?: string
  [key: string]: unknown
}

export interface AuthProfilesResponse {
  profiles: SessionProfileSummary[]
  [key: string]: unknown
}

export interface AuthBoundaryResult {
  url?: string
  allowed_by_profile?: boolean
  blocked_by_profile?: boolean
  reason?: string
  matched_rule?: string
  auth_profile_id?: string
  role_label?: string
  [key: string]: unknown
}

export interface AuthEndpointClassificationResponse {
  auth_required_endpoint_classification?: ApiRecord
  classified_endpoints?: ApiRecord[]
  [key: string]: unknown
}

export interface AuthenticatedCrawlResponse {
  auth_context_summary?: ApiRecord
  authenticated_crawl_summary?: ApiRecord
  authenticated_crawl_results?: ApiRecord[]
  authenticated_crawl_skipped?: ApiRecord[]
  authenticated_boundary_events?: ApiRecord[]
  auth_required_endpoint_classification?: ApiRecord
  [key: string]: unknown
}

export interface RoleProfile {
  role_id?: string
  role_name?: string
  role_label?: string
  description?: string
  linked_session_profile_id?: string | null
  linked_session_profile_name?: string | null
  test_account_label?: string | null
  tenant_label?: string | null
  user_type?: string
  expected_access_level?: string
  allowed_actions?: string[]
  disallowed_actions?: string[]
  sensitive_actions?: string[]
  notes?: string
  created_at?: string
  updated_at?: string
  [key: string]: unknown
}

export interface PermissionAction {
  action_id?: string
  action_name?: string
  action_type?: string
  description?: string
  endpoint_pattern?: string
  http_method?: string
  sensitivity?: string
  state_changing?: boolean
  destructive?: boolean
  requires_manual_validation?: boolean
  notes?: string
  [key: string]: unknown
}

export interface PermissionMatrix {
  matrix_id?: string
  matrix_name?: string
  target?: string
  roles?: unknown[]
  actions?: PermissionAction[]
  role_action_rules?: Array<Record<string, unknown>>
  endpoint_mappings?: Array<Record<string, unknown>>
  [key: string]: unknown
}

export interface RoleEndpointMatrixRow {
  role_id?: string
  role_label?: string
  tenant_label?: string
  endpoint?: string
  method?: string
  action_id?: string
  inferred_action?: string
  sensitivity?: string
  state_changing?: boolean
  destructive?: boolean
  expected_permission?: string
  validation_status?: string
  manual_plan_id?: string
  manual_validation_required?: boolean
  [key: string]: unknown
}

export interface ManualValidationPlan {
  plan_id?: string
  role_label?: string
  tenant_label?: string
  endpoint?: string
  inferred_action?: string
  expected_permission?: string
  safe_manual_steps?: string[]
  expected_secure_result?: string
  evidence_to_collect?: string[]
  risk_if_failed?: string
  safety_notes?: string[]
  status?: string
  [key: string]: unknown
}

export interface RoleMappingResponse {
  role_mapping_summary?: ApiRecord
  roles?: RoleProfile[]
  role_profiles?: RoleProfile[]
  permission_matrix?: PermissionMatrix
  permission_matrix_summary?: ApiRecord
  inferred_actions?: Array<Record<string, unknown>>
  endpoint_action_mappings?: Array<Record<string, unknown>>
  role_endpoint_matrix?: RoleEndpointMatrixRow[]
  manual_validation_plans?: ManualValidationPlan[]
  role_comparison_notes?: Array<Record<string, unknown>>
  safety_notes?: string[]
  [key: string]: unknown
}

export interface RoleEndpointMapRequest {
  roles: RoleProfile[]
  permission_matrix: PermissionMatrix
  endpoint_results: Array<Record<string, unknown>>
}

export interface RoleManualPlanRequest {
  role: RoleProfile
  endpoint: Record<string, unknown> | string
  expected_permission: string
}

export interface A01ManualTestPlan {
  test_plan_id?: string
  title?: string
  category?: string
  test_type?: string
  target?: string
  affected_url?: string
  normalised_url?: string
  endpoint_category?: string
  role_label?: string
  role_id?: string
  tenant_label?: string
  expected_permission?: string
  expected_secure_behaviour?: string
  test_preconditions?: string[]
  manual_steps?: string[]
  evidence_checklist?: ApiRecord
  observed_behaviour?: ApiRecord
  validation_status?: string
  risk_if_failed?: string
  recommendation?: string
  safety_notes?: string[]
  linked_a01_evidence_id?: string
  linked_endpoint_id?: string
  linked_role_matrix_id?: string
  linked_session_profile_id?: string
  [key: string]: unknown
}

export interface A01AccessObservation {
  observation_id?: string
  test_plan_id?: string
  observed_status?: string
  observed_status_code?: number | null
  observed_message_summary?: string
  observed_access_result?: string
  evidence_summary?: string
  evidence_file_path?: string
  redaction_status?: string
  tester_notes?: string
  observed_at?: string
  [key: string]: unknown
}

export interface A01AccessRetest {
  retest_id?: string
  test_plan_id?: string
  original_observed_result?: string
  remediation_summary?: string
  retest_steps?: string[]
  retest_observed_result?: string
  retest_status?: string
  retest_notes?: string
  retested_at?: string
  [key: string]: unknown
}

export interface AccessTestPlannerResponse {
  access_control_test_plans?: A01ManualTestPlan[]
  access_control_test_plan?: A01ManualTestPlan
  access_control_observations?: A01AccessObservation[]
  access_control_observation?: A01AccessObservation
  access_control_retests?: A01AccessRetest[]
  access_control_retest?: A01AccessRetest
  a01_manual_validation_summary?: ApiRecord
  a01_report_template?: ApiRecord
  [key: string]: unknown
}

export interface AccessTestCreateRequest {
  role: RoleProfile
  endpoint: Record<string, unknown> | string
  expected_permission: string
  test_type: string
}

export interface AccessTestObserveRequest {
  test_plan_id: string
  observed_access_result: string
  observed_status_code?: number | null
  observed_message_summary?: string
  evidence_summary?: string
  evidence_file_path?: string
  tester_notes?: string
}

export interface ParameterReplayPlan {
  replay_plan_id?: string
  title?: string
  target?: string
  affected_url?: string
  normalised_url?: string
  method?: string
  endpoint_category?: string
  parameter_name?: string
  parameter_location?: string
  parameter_type?: string
  related_owasp_categories?: string[]
  role_label?: string
  expected_permission?: string
  replay_intent?: string
  manual_steps?: string[]
  safe_request_template_id?: string
  expected_secure_behaviour?: string
  observed_behaviour?: ApiRecord
  validation_status?: string
  evidence_checklist?: ApiRecord
  retest_status?: string
  safety_notes?: string[]
  [key: string]: unknown
}

export interface RedactedRequestTemplate {
  template_id?: string
  title?: string
  method?: string
  url_template?: string
  normalised_url?: string
  headers_redacted?: Record<string, string>
  cookies_redacted?: string[]
  query_parameters?: Record<string, string[]>
  path_parameters?: Record<string, string>
  form_fields?: Record<string, string>
  json_body_schema?: ApiRecord
  sensitive_fields_redacted?: string[]
  auth_context_summary?: ApiRecord
  boundary_status?: string
  blocked_by_default?: boolean
  state_changing?: boolean
  destructive?: boolean
  safe_to_review_manually?: boolean
  warnings?: string[]
  [key: string]: unknown
}

export interface ParameterReplayObservation {
  observation_id?: string
  replay_plan_id?: string
  observed_access_result?: string
  observed_status_code?: number | null
  observed_message_summary?: string
  observed_parameter_effect?: string
  evidence_summary?: string
  evidence_file_path?: string
  redaction_status?: string
  tester_notes?: string
  observed_at?: string
  [key: string]: unknown
}

export interface ParameterReplayRetest {
  retest_id?: string
  replay_plan_id?: string
  original_observed_result?: string
  remediation_summary?: string
  retest_steps?: string[]
  retest_observed_result?: string
  retest_status?: string
  retest_notes?: string
  retested_at?: string
  [key: string]: unknown
}

export interface ParameterReplayPlannerResponse {
  parameter_replay_plans?: ParameterReplayPlan[]
  parameter_replay_plan?: ParameterReplayPlan
  redacted_request_templates?: RedactedRequestTemplate[]
  redacted_request_template?: RedactedRequestTemplate
  parameter_replay_observations?: ParameterReplayObservation[]
  parameter_replay_observation?: ParameterReplayObservation
  parameter_replay_retests?: ParameterReplayRetest[]
  parameter_replay_retest?: ParameterReplayRetest
  parameter_replay_summary?: ApiRecord
  parameter_replay_report_template?: ApiRecord
  [key: string]: unknown
}

export interface ReplayPlanCreateRequest {
  endpoint: Record<string, unknown> | string
  parameter: Record<string, unknown> | string
  intent?: string
  role?: Record<string, unknown> | string | null
}

export interface ReplayPlanObserveRequest {
  replay_plan_id: string
  observed_access_result: string
  observed_status_code?: number | null
  observed_message_summary?: string
  observed_parameter_effect?: string
  evidence_summary?: string
  evidence_file_path?: string
  tester_notes?: string
}

export interface BusinessLogicWorkflowCandidate {
  workflow_candidate_id?: string
  title?: string
  workflow_type?: string
  target?: string
  affected_url?: string
  normalised_url?: string
  endpoint_category?: string
  related_parameters?: string[]
  related_roles?: string[]
  related_owasp_categories?: string[]
  workflow_sensitivity?: string
  state_changing?: boolean
  destructive_or_financial?: boolean
  candidate_score?: number
  confidence?: string
  [key: string]: unknown
}

export interface BusinessLogicReviewPlan {
  review_plan_id?: string
  title?: string
  workflow_type?: string
  target?: string
  affected_urls?: string[]
  related_parameters?: string[]
  related_roles?: string[]
  related_owasp_categories?: string[]
  expected_business_rule?: string
  expected_secure_behaviour?: string
  abuse_cases?: ApiRecord
  state_transition_map?: ApiRecord
  manual_steps?: string[]
  evidence_checklist?: ApiRecord
  observed_behaviour?: ApiRecord
  validation_status?: string
  risk_if_failed?: string
  recommendation?: string
  retest_status?: string
  safety_notes?: string[]
  linked_candidates?: string[]
  linked_replay_plans?: string[]
  linked_access_test_plans?: string[]
  [key: string]: unknown
}

export interface BusinessLogicObservation {
  observation_id?: string
  review_plan_id?: string
  observed_result?: string
  observed_status_code?: number | null
  observed_message_summary?: string
  observed_workflow_effect?: string
  evidence_summary?: string
  redaction_status?: string
  tester_notes?: string
  [key: string]: unknown
}

export interface BusinessLogicRetest {
  retest_id?: string
  review_plan_id?: string
  retest_status?: string
  retest_observed_result?: string
  retest_notes?: string
  [key: string]: unknown
}

export interface BusinessLogicReviewResponse {
  business_logic_workflow_candidates?: BusinessLogicWorkflowCandidate[]
  business_logic_review_plans?: BusinessLogicReviewPlan[]
  business_logic_review_plan?: BusinessLogicReviewPlan
  business_logic_state_transition_map?: ApiRecord
  business_logic_abuse_case_checklist?: ApiRecord
  business_logic_observation?: BusinessLogicObservation
  business_logic_observations?: BusinessLogicObservation[]
  business_logic_retest?: BusinessLogicRetest
  business_logic_retests?: BusinessLogicRetest[]
  business_logic_report_template?: ApiRecord
  business_logic_summary?: ApiRecord
  [key: string]: unknown
}

export interface BusinessLogicCreateRequest {
  workflow: string
  endpoint: Record<string, unknown> | string
  role?: Record<string, unknown> | string | null
}

export interface OWASPCategory {
  owasp_id?: string
  name?: string
  short_description?: string
  recommendation_theme?: string
  limitation?: string
  [key: string]: unknown
}

export interface OWASPMapping {
  owasp_id?: string
  owasp_name?: string
  confidence?: string
  mapping_reason?: string
  source?: string
  limitation?: string
  manual_validation_required?: boolean
  [key: string]: unknown
}

export interface OWASPSummary {
  enabled?: boolean
  version?: string
  mapped_findings_count?: number
  unmapped_findings_count?: number
  mapped_endpoint_candidates_count?: number
  mapped_parameter_candidates_count?: number
  category_counts?: Record<string, number>
  category_confidence_counts?: Record<string, Record<string, number>>
  highest_signal_categories?: Array<{ owasp_id?: string; owasp_name?: string; count?: number }>
  coverage_gaps?: Array<{ owasp_id?: string; owasp_name?: string; explanation?: string }>
  manual_validation_required_count?: number
  limitations?: string[]
  [key: string]: unknown
}

export interface OWASPMappedItem extends OWASPMapping {
  item_type?: string
  item_key?: string
  title?: string
  category?: string
}

export interface OWASPCategoriesResponse {
  version?: string
  categories: OWASPCategory[]
  [key: string]: unknown
}

export interface OWASPMapRequest {
  findings?: Finding[]
  endpoint_results?: EndpointResult[]
  parameter_results?: ParameterResult[]
}

export interface OWASPMapResponse {
  owasp_top10_summary?: OWASPSummary
  owasp_top10_mapped_items?: OWASPMappedItem[]
  [key: string]: unknown
}

export type OWASPEvidenceStrength = 'weak_indicator' | 'strong_indicator' | 'confirmed_finding' | 'informational' | 'not_assessed'
export type OWASPAssessmentStatus = 'detected_indicator' | 'needs_manual_validation' | 'confirmed' | 'confirmed_findings' | 'strong_indicators' | 'weak_indicators' | 'informational_only' | 'no_indicators_observed' | 'not_detected' | 'not_assessed' | 'coverage_gap'
export type OWASPCoverageStatus = 'assessed' | 'partially_assessed' | 'manual_review_required' | 'not_assessed' | 'manual_only' | 'coverage_gap'

export interface OWASPEvidenceItem {
  evidence_id?: string
  source?: string
  source_id?: string
  title?: string
  affected_url?: string
  affected_parameter?: string
  endpoint_category?: string
  finding_category?: string
  observed_signal?: string
  owasp_id?: string
  owasp_name?: string
  confidence?: 'Low' | 'Medium' | 'High' | string
  evidence_strength?: OWASPEvidenceStrength | string
  assessment_status?: OWASPAssessmentStatus | string
  manual_validation_required?: boolean
  evidence_summary?: string
  recommendation_theme?: string
  limitation?: string
  created_at?: string
  [key: string]: unknown
}

export interface OWASPCategoryResult {
  owasp_id?: string
  category?: string
  name?: string
  assessment_status?: OWASPAssessmentStatus | string
  highest_confidence?: 'Low' | 'Medium' | 'High' | string
  evidence_count?: number
  strongest_evidence?: string
  confirmed_count?: number
  strong_indicator_count?: number
  weak_indicator_count?: number
  manual_validation_required_count?: number
  manual_validation_required?: boolean
  coverage_status?: OWASPCoverageStatus | string
  recommendation_summary?: string
  top_evidence?: OWASPEvidenceItem[]
  recommendation_themes?: string[]
  limitations?: string
  [key: string]: unknown
}

export interface OWASPCoverageGap {
  category?: string
  owasp_id?: string
  owasp_name?: string
  gap_title?: string
  why_it_matters?: string
  recommended_next_step?: string
  severity_context?: string
  coverage_status?: OWASPCoverageStatus | string
  explanation?: string
  manual_validation_required?: boolean
  [key: string]: unknown
}

export interface OWASPAssessmentSummary {
  enabled?: boolean
  owasp_version?: string
  target?: string
  generated_at?: string
  total_evidence_items?: number
  confirmed_findings_count?: number
  strong_indicators_count?: number
  weak_indicators_count?: number
  manual_validation_required_count?: number
  categories_assessed_count?: number
  categories_with_indicators_count?: number
  coverage_gaps_count?: number
  highest_signal_categories?: Array<{ owasp_id?: string; owasp_name?: string; evidence_count?: number; highest_confidence?: string }>
  assessment_quality_score?: number
  assessment_quality_label?: string
  limitations?: string[]
  [key: string]: unknown
}

export interface OWASPAssessmentBuildRequest {
  target?: string
  owasp_assessment_summary?: OWASPAssessmentSummary
  owasp_category_results?: OWASPCategoryResult[]
  owasp_evidence_items?: OWASPEvidenceItem[]
  findings?: Finding[]
  endpoint_results?: EndpointResult[]
  parameter_results?: ParameterResult[]
  safe_validation_results?: SafeValidationResult[]
  evidence_records?: ApiRecord[]
}

export interface OWASPAssessmentResponse {
  owasp_assessment_summary?: OWASPAssessmentSummary
  owasp_assessment_report?: OWASPAssessmentReport
  owasp_category_results?: OWASPCategoryResult[]
  owasp_evidence_items?: OWASPEvidenceItem[]
  owasp_coverage_matrix?: OWASPCategoryResult[]
  owasp_manual_validation_checklist?: OWASPManualValidationItem[]
  owasp_developer_recommendations?: OWASPDeveloperRecommendation[]
  owasp_coverage_gaps?: OWASPCoverageGap[]
  [key: string]: unknown
}

export interface OWASPManualValidationItem {
  category?: string
  item?: string
  priority?: string
  reason?: string
  suggested_evidence?: string
  status?: 'pending' | 'done' | 'not_applicable' | string
  [key: string]: unknown
}

export interface OWASPDeveloperRecommendation {
  category?: string
  issue_theme?: string
  recommendation?: string
  implementation_hint?: string
  validation_hint?: string
  references_label?: string
  [key: string]: unknown
}

export interface OWASPAssessmentReport {
  report_id?: string
  target?: string
  generated_at?: string
  owasp_version?: string
  assessment_scope?: ApiRecord
  executive_summary?: ApiRecord
  assessment_quality_score?: { score?: number; label?: string; limitation?: string; [key: string]: unknown }
  overall_coverage_status?: string
  category_results?: OWASPCategoryResult[]
  evidence_strength_summary?: ApiRecord
  manual_validation_summary?: { manual_validation_required_count?: number; checklist?: OWASPManualValidationItem[]; [key: string]: unknown }
  coverage_gaps?: OWASPCoverageGap[]
  top_risks?: ApiRecord[]
  developer_recommendations?: OWASPDeveloperRecommendation[]
  report_limitations?: string[]
  safe_testing_statement?: string
  markdown_report_path?: string
  [key: string]: unknown
}

export interface OWASPReportBuildResponse {
  owasp_assessment_report?: OWASPAssessmentReport
  markdown_report_path?: string
  download_url?: string
  [key: string]: unknown
}

export interface OWASPAssessmentRulesResponse {
  version?: string
  categories?: OWASPCategory[]
  [key: string]: unknown
}

export interface A01AccessControlSummary {
  enabled?: boolean
  target?: string
  generated_at?: string
  total_evidence_items?: number
  high_interest_count?: number
  medium_interest_count?: number
  low_interest_count?: number
  informational_count?: number
  manual_validation_required_count?: number
  object_id_candidate_count?: number
  function_level_candidate_count?: number
  tenant_boundary_candidate_count?: number
  sensitive_resource_candidate_count?: number
  role_permission_indicator_count?: number
  api_access_control_candidate_count?: number
  rule_group_counts?: Record<string, number>
  highest_confidence?: string
  top_candidates?: ApiRecord[]
  recommendations?: string[]
  limitations?: string[]
  [key: string]: unknown
}

export interface A01EvidenceTemplate {
  candidate_title?: string
  affected_endpoint?: string
  parameter_or_object_identifier?: string
  candidate_type?: string
  why_it_may_matter?: string
  safe_manual_validation_steps?: string[]
  expected_secure_behaviour?: string
  evidence_needed_for_confirmation?: string
  risk_if_confirmed?: string
  recommendation?: string
  [key: string]: unknown
}

export interface A01AccessControlEvidenceItem {
  evidence_id?: string
  rule_id?: string
  rule_group?: string
  title?: string
  affected_url?: string
  affected_host?: string
  affected_parameter?: string
  endpoint_category?: string
  object_type_hint?: string
  access_control_candidate_type?: string
  evidence_strength?: string
  candidate_score?: number
  interest_label?: string
  confidence?: string
  safe_evidence_summary?: string
  manual_validation_required?: boolean
  manual_test_plan_id?: string
  recommended_manual_steps?: string[]
  recommendation?: string
  limitation?: string
  evidence_template?: A01EvidenceTemplate
  source?: string
  created_at?: string
  [key: string]: unknown
}

export interface A01AssessmentRequest {
  target?: string
  endpoint_results?: ApiRecord[]
  parameter_results?: ApiRecord[]
  evidence_records?: ApiRecord[]
}

export interface A01AssessmentResponse {
  a01_access_control_summary?: A01AccessControlSummary
  a01_access_control_evidence?: A01AccessControlEvidenceItem[]
}

export interface A01ManualPlanRequest {
  evidence_item?: ApiRecord
}

export interface A01ManualPlanResponse {
  manual_validation_plan?: ApiRecord
  evidence_template?: A01EvidenceTemplate
}

export interface A03SupplyChainSummary {
  enabled?: boolean
  target?: string
  generated_at?: string
  total_evidence_items?: number
  strong_indicators_count?: number
  weak_indicators_count?: number
  informational_count?: number
  manual_validation_required_count?: number
  component_hint_count?: number
  version_exposure_count?: number
  dependency_metadata_exposure_count?: number
  sbom_component_count?: number
  cve_match_count?: number
  cpe_match_count?: number
  source_map_indicator_count?: number
  third_party_script_count?: number
  rule_group_counts?: Record<string, number>
  highest_confidence?: string
  top_risks?: string[]
  recommendations?: string[]
  limitations?: string[]
  [key: string]: unknown
}

export interface A03SupplyChainEvidenceItem {
  evidence_id?: string
  rule_id?: string
  rule_group?: string
  title?: string
  affected_url?: string
  affected_host?: string
  component_name?: string
  component_version?: string
  component_type?: string
  package_ecosystem?: string
  cpe?: string
  purl?: string
  cve_ids?: string[]
  cvss_score?: number | string | null
  epss_score?: number | string | null
  exploit_metadata?: ApiRecord
  evidence_strength?: string
  confidence?: string
  safe_evidence_summary?: string
  recommendation?: string
  manual_validation_required?: boolean
  source?: string
  created_at?: string
  limitation?: string
  metadata_filename?: string
  [key: string]: unknown
}

export interface A03AssessmentRequest {
  target?: string
  headers?: ApiRecord
  html_snippet?: string
  scripts?: unknown[]
  endpoint_results?: ApiRecord[]
  sbom_components?: ApiRecord[]
  vuln_intel?: ApiRecord
}

export interface A03AssessmentResponse {
  a03_supply_chain_summary?: A03SupplyChainSummary
  a03_supply_chain_evidence?: A03SupplyChainEvidenceItem[]
}

export interface A08IntegritySummary {
  enabled?: boolean
  target?: string
  generated_at?: string
  total_evidence_items?: number
  high_interest_count?: number
  medium_interest_count?: number
  low_interest_count?: number
  informational_count?: number
  manual_validation_required_count?: number
  upload_candidate_count?: number
  import_export_candidate_count?: number
  webhook_callback_candidate_count?: number
  update_workflow_candidate_count?: number
  sri_indicator_count?: number
  trusted_data_boundary_candidate_count?: number
  deserialisation_candidate_count?: number
  rule_group_counts?: Record<string, number>
  highest_confidence?: string
  top_candidates?: A08IntegrityEvidenceItem[]
  recommendations?: string[]
  limitations?: string[]
  [key: string]: unknown
}

export interface A08IntegrityEvidenceTemplate {
  candidate_title?: string
  affected_endpoint?: string
  workflow_type?: string
  integrity_boundary?: string
  why_it_may_matter?: string
  safe_manual_validation_steps?: string[]
  expected_secure_behaviour?: string
  evidence_needed_for_confirmation?: string
  risk_if_confirmed?: string
  recommendation?: string
}

export interface A08IntegrityEvidenceItem {
  evidence_id?: string
  rule_id?: string
  rule_group?: string
  title?: string
  affected_url?: string
  affected_host?: string
  affected_parameter?: string
  workflow_type?: string
  integrity_candidate_type?: string
  evidence_strength?: string
  candidate_score?: number
  interest_label?: string
  confidence?: string
  safe_evidence_summary?: string
  manual_validation_required?: boolean
  manual_test_plan_id?: string
  recommended_manual_steps?: string[]
  recommendation?: string
  limitation?: string
  resource_type?: string
  integrity_present?: boolean
  third_party_domain?: string
  evidence_template?: A08IntegrityEvidenceTemplate
  source?: string
  created_at?: string
  [key: string]: unknown
}

export interface A08AssessmentRequest {
  target?: string
  endpoint_results?: ApiRecord[]
  parameter_results?: ApiRecord[]
  forms?: ApiRecord[]
  scripts?: unknown[]
  stylesheets?: unknown[]
  html_snippet?: string
}

export interface A08AssessmentResponse {
  a08_integrity_summary?: A08IntegritySummary
  a08_integrity_evidence?: A08IntegrityEvidenceItem[]
}

export interface A08ManualPlanRequest {
  evidence_item?: ApiRecord
}

export interface A08ManualPlanResponse {
  manual_validation_plan?: ApiRecord
  evidence_template?: A08IntegrityEvidenceTemplate
}

export interface SBOMAnalyseRequest {
  sbom?: ApiRecord
  use_vuln_intel?: boolean
  vuln_intel?: ApiRecord
}

export interface SBOMAnalyseResponse {
  components?: ApiRecord[]
  a03_supply_chain_summary?: A03SupplyChainSummary
  a03_supply_chain_evidence?: A03SupplyChainEvidenceItem[]
}

export interface A04CryptoSummary {
  enabled?: boolean
  target?: string
  generated_at?: string
  total_evidence_items?: number
  strong_indicators_count?: number
  weak_indicators_count?: number
  informational_count?: number
  manual_validation_required_count?: number
  rule_group_counts?: Record<string, number>
  https_urls_count?: number
  http_urls_count?: number
  insecure_cookie_count?: number
  hsts_issue_count?: number
  mixed_content_indicator_count?: number
  tls_metadata_available?: boolean
  highest_confidence?: string
  top_risks?: string[]
  recommendations?: string[]
  limitations?: string[]
  [key: string]: unknown
}

export interface A04CryptoEvidenceItem {
  evidence_id?: string
  rule_id?: string
  rule_group?: string
  title?: string
  affected_url?: string
  affected_host?: string
  scheme?: string
  evidence_strength?: string
  confidence?: string
  observed_value?: string
  safe_evidence_summary?: string
  recommendation?: string
  manual_validation_required?: boolean
  source?: string
  created_at?: string
  cookie_name?: string
  missing_attributes?: string[]
  resource_type?: string
  resource_scheme?: string
  [key: string]: unknown
}

export interface A04TlsMetadata {
  host?: string
  port?: number
  metadata_available?: boolean
  subject_common_name?: string
  issuer_common_name?: string
  not_before?: string
  not_after?: string
  expired?: boolean | null
  days_until_expiry?: number | null
  hostname_match?: boolean | null
  self_signed_indicator?: boolean | null
  error?: string
  limitations?: string[]
  [key: string]: unknown
}

export interface A04AssessmentRequest {
  target?: string
  headers?: Record<string, unknown>
  set_cookie_headers?: string[]
  urls?: string[]
  forms?: Array<Record<string, unknown>>
  html_snippet?: string
}

export interface A04AssessmentResponse {
  a04_crypto_summary?: A04CryptoSummary
  a04_crypto_evidence?: A04CryptoEvidenceItem[]
}

export interface A07AuthenticationSummary {
  enabled?: boolean
  target?: string
  generated_at?: string
  total_evidence_items?: number
  strong_indicators_count?: number
  weak_indicators_count?: number
  informational_count?: number
  manual_validation_required_count?: number
  auth_endpoint_count?: number
  login_form_count?: number
  password_reset_endpoint_count?: number
  session_cookie_indicator_count?: number
  remember_me_indicator_count?: number
  csrf_indicator_count?: number
  rate_limit_indicator_count?: number
  protocol_surface_indicator_count?: number
  rule_group_counts?: Record<string, number>
  highest_confidence?: string
  top_risks?: string[]
  recommendations?: string[]
  limitations?: string[]
  [key: string]: unknown
}

export interface A07AuthenticationEvidenceItem {
  evidence_id?: string
  rule_id?: string
  rule_group?: string
  title?: string
  affected_url?: string
  affected_host?: string
  affected_parameter?: string
  evidence_strength?: string
  confidence?: string
  observed_value?: string
  safe_evidence_summary?: string
  recommendation?: string
  manual_validation_required?: boolean
  source?: string
  created_at?: string
  endpoint_type?: string
  cookie_name?: string
  missing_attributes?: string[]
  persistence_indicator?: boolean
  password_field_detected?: boolean
  csrf_like_field_detected?: boolean
  csrf_like_field_names?: string[]
  form_action_scheme?: string
  remember_me_checkbox?: boolean
  [key: string]: unknown
}

export interface A07AssessmentRequest {
  target?: string
  urls?: string[]
  headers?: Record<string, unknown>
  set_cookie_headers?: string[]
  forms?: Array<Record<string, unknown>>
  endpoint_results?: Array<Record<string, unknown>>
  parameter_results?: Array<Record<string, unknown>>
}

export interface A07AssessmentResponse {
  a07_authentication_summary?: A07AuthenticationSummary
  a07_authentication_evidence?: A07AuthenticationEvidenceItem[]
}

export interface A05InjectionSummary {
  enabled?: boolean
  target?: string
  generated_at?: string
  total_evidence_items?: number
  strong_indicators_count?: number
  weak_indicators_count?: number
  informational_count?: number
  manual_validation_required_count?: number
  parameter_candidate_count?: number
  form_input_candidate_count?: number
  api_input_candidate_count?: number
  reflection_observed_count?: number
  script_like_reflection_count?: number
  attribute_like_reflection_count?: number
  json_like_reflection_count?: number
  rule_group_counts?: ApiRecord
  highest_confidence?: string
  top_risks?: string[]
  recommendations?: string[]
  limitations?: string[]
}

export interface A05InjectionEvidenceItem {
  evidence_id?: string
  rule_id?: string
  rule_group?: string
  title?: string
  affected_url?: string
  affected_host?: string
  affected_parameter?: string
  input_type?: string
  evidence_strength?: string
  confidence?: string
  observed_value?: string
  safe_evidence_summary?: string
  reflection_context?: string
  recommendation?: string
  manual_validation_required?: boolean
  source?: string
  created_at?: string
  candidate_type?: string
  potential_issue?: string
  marker_reflected?: boolean
  redacted_snippet?: string
  form_action?: string
  input_names?: string[]
  input_types?: string[]
  hidden_field_names?: string[]
  candidate_reason?: string
  api_pattern?: string
  parameter_names?: string[]
  candidate_score?: number
  [key: string]: unknown
}

export interface A05AssessmentRequest {
  target?: string
  endpoint_results?: ApiRecord[]
  parameter_results?: ApiRecord[]
  forms?: ApiRecord[]
  safe_reflection?: boolean
  max_reflection_checks?: number
  request_delay?: number
}

export interface A05AssessmentResponse {
  a05_injection_summary?: A05InjectionSummary
  a05_injection_evidence?: A05InjectionEvidenceItem[]
}

export interface A10ErrorHandlingSummary {
  enabled?: boolean
  target?: string
  generated_at?: string
  total_evidence_items?: number
  strong_indicators_count?: number
  weak_indicators_count?: number
  informational_count?: number
  manual_validation_required_count?: number
  stack_trace_count?: number
  database_error_count?: number
  framework_error_count?: number
  debug_page_count?: number
  status_5xx_count?: number
  fail_safe_review_count?: number
  sensitive_error_content_count?: number
  rule_group_counts?: Record<string, number>
  highest_confidence?: string
  top_risks?: string[]
  recommendations?: string[]
  limitations?: string[]
  [key: string]: unknown
}

export interface A10ErrorHandlingEvidenceItem {
  evidence_id?: string
  rule_id?: string
  rule_group?: string
  title?: string
  affected_url?: string
  affected_host?: string
  status_code?: number | null
  evidence_strength?: string
  confidence?: string
  observed_pattern?: string
  safe_evidence_summary?: string
  redacted_snippet?: string
  recommendation?: string
  manual_validation_required?: boolean
  source?: string
  created_at?: string
  framework_hint?: string
  pattern_matched?: string
  endpoint_category?: string
  [key: string]: unknown
}

export interface A10ResponseObservation {
  url?: string
  status_code?: number | null
  body_snippet?: string
  headers?: Record<string, unknown>
  source?: string
  endpoint_category?: string
}

export interface A10AssessmentRequest {
  target?: string
  responses?: A10ResponseObservation[]
  endpoint_results?: Array<Record<string, unknown>>
}

export interface A10AssessmentResponse {
  a10_error_handling_summary?: A10ErrorHandlingSummary
  a10_error_handling_evidence?: A10ErrorHandlingEvidenceItem[]
}

export interface SafeValidationTarget {
  url: string
  candidate_type?: string
  parameter?: string
  source?: string
}

export interface SafeValidationSummary {
  enabled?: boolean
  input_targets_count?: number
  in_scope_targets_count?: number
  out_of_scope_targets_count?: number
  checks_requested?: string[]
  checks_run?: number
  checks_skipped?: number
  indicators_found?: number
  request_count?: number
  rate_limit_applied?: boolean
  limitations?: string[]
  [key: string]: unknown
}

export interface SafeValidationResult {
  url?: string
  candidate_type?: string
  parameter?: string
  check_name?: string
  status?: string
  indicator_found?: boolean
  confidence?: string
  evidence_summary?: ApiRecord
  request_method?: string
  status_code?: number | null
  response_time_ms?: number
  owasp_categories?: OWASPMapping[]
  manual_validation_note?: string
  limitation?: string
  [key: string]: unknown
}

export interface SafeValidationSkipped {
  url?: string
  candidate_type?: string
  reason?: string
  scope_reason?: string
  [key: string]: unknown
}

export interface SafeValidationRequest {
  targets: SafeValidationTarget[]
  scope_file?: string
  enforce_scope?: boolean
  checks?: string[]
  request_delay?: number
  max_requests_per_minute?: number
  timeout?: number
  max_validation_requests?: number
  safe_active_confirm?: boolean
}

export interface SafeValidationResponse {
  safe_active_validation?: SafeValidationSummary
  safe_active_validation_results?: SafeValidationResult[]
  safe_active_validation_skipped?: SafeValidationSkipped[]
  findings?: Finding[]
  [key: string]: unknown
}

export type SubmissionStatus =
  | 'draft'
  | 'ready_for_review'
  | 'submitted'
  | 'triaged'
  | 'accepted'
  | 'duplicate'
  | 'informative'
  | 'not_applicable'
  | 'resolved'
  | 'paid'
  | 'closed'

export type RetestStatus =
  | 'not_required'
  | 'retest_required'
  | 'retest_in_progress'
  | 'retest_passed'
  | 'retest_failed'
  | 'retest_blocked'

export interface SubmissionRecord {
  submission_id?: string
  report_id?: string
  evidence_ids?: string[]
  finding_title?: string
  program_name?: string
  platform?: string
  submission_url?: string
  external_reference?: string
  status?: SubmissionStatus | string
  severity_submitted?: string
  severity_accepted?: string
  duplicate_of?: string
  bounty_amount?: string
  bounty_currency?: string
  submitted_at?: string
  triaged_at?: string
  accepted_at?: string
  resolved_at?: string
  paid_at?: string
  next_follow_up_date?: string
  notes?: string
  safe_notes_redacted?: boolean
  created_at?: string
  updated_at?: string
  timeline?: SubmissionTimelineEvent[]
  retests?: RetestRecord[]
  [key: string]: unknown
}

export interface SubmissionTimelineEvent {
  event_id?: string
  submission_id?: string
  event_type?: string
  old_status?: string
  new_status?: string
  note?: string
  created_at?: string
  [key: string]: unknown
}

export interface RetestRecord {
  retest_id?: string
  submission_id?: string
  report_id?: string
  target?: string
  affected_url?: string
  status?: RetestStatus | string
  requested_at?: string
  retested_at?: string
  retest_result?: string
  evidence_id?: string
  notes?: string
  created_at?: string
  updated_at?: string
  [key: string]: unknown
}

export interface SubmissionSummary {
  total_count?: number
  draft_count?: number
  submitted_count?: number
  triaged_count?: number
  accepted_count?: number
  duplicate_count?: number
  resolved_count?: number
  paid_count?: number
  retest_required_count?: number
  retest_passed_count?: number
  retest_failed_count?: number
  total_bounty_amount_by_currency?: Record<string, number>
  [key: string]: unknown
}

export interface SubmissionsResponse {
  submissions: SubmissionRecord[]
}

export interface RetestsResponse {
  retests: RetestRecord[]
}

export interface SubmissionTimelineResponse {
  events: SubmissionTimelineEvent[]
}

export type WorkflowStepStatus = 'Not started' | 'Ready' | 'In progress' | 'Completed' | 'Needs review'

export interface WorkflowStep {
  id: string
  label: string
  status: WorkflowStepStatus
  count?: number | string
  readiness?: string
  nextAction?: string
  sectionId?: string
  detail?: string
}

export interface WorkflowSummary {
  inScopePrograms?: number
  liveAssets?: number
  highInterestEndpoints?: number
  owaspIndicators?: number
  safeValidationIndicators?: number
  evidenceRecords?: number
  draftReports?: number
  submittedFindings?: number
  retestsRequired?: number
  acceptedFindings?: number
  paidFindings?: number
}

export interface WorkflowTimelineEvent {
  event_time?: string
  event_type?: string
  title?: string
  source?: string
}

export interface WorkflowReadiness {
  score: number
  label: string
}

export interface NextBestAction {
  label: string
  sectionId?: string
  reason?: string
}

export type DuplicateStatus = 'unique' | 'exact_duplicate' | 'likely_duplicate' | 'related' | string
export type DuplicateConfidence = 'Exact' | 'High' | 'Medium' | 'Low' | string

export interface FindingFingerprint {
  fingerprint_id?: string
  fingerprint_version?: string
  fingerprint_hash?: string
  fingerprint_short?: string
  target_normalised?: string
  host?: string
  path_normalised?: string
  parameter_names?: string[]
  issue_type?: string
  owasp_category?: string
  source?: string
  evidence_type?: string
  cve?: string
  service?: string
  port?: number | string | null
  method?: string
  created_at?: string
  [key: string]: unknown
}

export interface DuplicateResult {
  duplicate_status?: DuplicateStatus
  duplicate_group_id?: string
  duplicate_confidence?: DuplicateConfidence
  duplicate_reason?: string
  existing_item_references?: ApiRecord[]
  [key: string]: unknown
}

export interface DuplicateCheckRequest {
  url?: string
  target?: string
  host?: string
  path?: string
  title?: string
  issue_type: string
  parameter_names?: string[]
  parameter?: string
  source?: string
  owasp_category?: string
  cve?: string
  service?: string
  port?: number
  method?: string
  item_type?: string
  item_id?: string
  store?: boolean
}

export interface DuplicateCheckResponse {
  fingerprint: FindingFingerprint
  duplicate_result: DuplicateResult
  [key: string]: unknown
}

export interface DuplicateGroupMember {
  duplicate_group_id?: string
  fingerprint_id?: string
  relationship?: string
  confidence?: DuplicateConfidence
  reason?: string
  title?: string
  item_type?: string
  item_id?: string
  fingerprint_hash?: string
  host?: string
  path_normalised?: string
  issue_type?: string
  created_at?: string
  [key: string]: unknown
}

export interface DuplicateGroup {
  duplicate_group_id?: string
  group_hash?: string
  primary_fingerprint_id?: string
  duplicate_status?: DuplicateStatus
  confidence?: DuplicateConfidence
  title?: string
  member_count?: number
  members?: DuplicateGroupMember[]
  created_at?: string
  updated_at?: string
  [key: string]: unknown
}

export interface DuplicateSummary {
  enabled?: boolean
  total_fingerprints?: number
  unique_findings?: number
  exact_duplicates?: number
  likely_duplicates?: number
  related_findings?: number
  duplicate_groups_count?: number
  limitations?: string[]
  [key: string]: unknown
}

export type DateRangeOption = 'all-time' | 'last-7-days' | 'last-30-days' | 'last-90-days' | 'this-year' | 'custom'

export interface MetricsDateRange {
  range: DateRangeOption | string
  start_date?: string | null
  end_date?: string | null
}

export interface QualityIndicator {
  score: number
  label: 'Getting Started' | 'Improving' | 'Strong Workflow' | 'High Quality' | string
  reasons: string[]
}

export interface ProgramPerformance {
  program_name: string
  total_submissions: number
  accepted: number
  duplicates: number
  informative: number
  not_applicable: number
  resolved: number
  paid: number
  acceptance_rate: number
  duplicate_rate: number
  total_bounty_by_currency: Record<string, number>
  average_time_to_triage_days?: number | null
  last_activity?: string
}

export interface VulnerabilityClassMetric {
  class_name: string
  count: number
  accepted_count: number
  duplicate_count: number
  acceptance_rate: number
  average_severity: number
}

export interface MonthlyActivityPoint {
  month: string
  evidence_created: number
  reports_created: number
  submissions_created: number
  accepted: number
  duplicates: number
  resolved: number
  paid: number
  retests_completed: number
}

export interface OutcomeDistribution {
  outcome: string
  count: number
}

export interface BugIntelligenceMetrics {
  enabled: boolean
  generated_at: string
  date_range: MetricsDateRange
  total_evidence_records: number
  total_reports_created: number
  total_submissions: number
  total_accepted: number
  total_duplicates: number
  total_informative: number
  total_not_applicable: number
  total_resolved: number
  total_paid: number
  total_retests: number
  retest_passed_count: number
  retest_failed_count: number
  acceptance_rate: number
  duplicate_rate: number
  informative_rate: number
  resolution_rate: number
  average_time_to_report_hours?: number | null
  average_time_to_triage_days?: number | null
  average_time_to_resolution_days?: number | null
  average_time_to_payment_days?: number | null
  total_bounty_by_currency: Record<string, number>
  average_bounty_by_currency: Record<string, number>
  top_programs: ProgramPerformance[]
  top_vulnerability_classes: VulnerabilityClassMetric[]
  top_owasp_categories: Array<{ category: string; count: number }>
  monthly_activity: MonthlyActivityPoint[]
  outcome_distribution: OutcomeDistribution[]
  quality_indicators: QualityIndicator
  limitations: string[]
}

export interface BugIntelligenceMetricsResponse {
  bug_intelligence_metrics: BugIntelligenceMetrics
}

export interface DuplicateGroupsResponse {
  summary?: DuplicateSummary
  groups: DuplicateGroup[]
  [key: string]: unknown
}

export interface EvidenceVaultItem {
  evidence_id?: string
  title?: string
  evidence_type?: string
  source_module?: string
  related_target?: string
  related_url?: string
  related_host?: string
  related_owasp_categories?: string[]
  linked_finding_ids?: string[]
  linked_test_plan_ids?: string[]
  linked_replay_plan_ids?: string[]
  linked_business_logic_plan_ids?: string[]
  linked_submission_ids?: string[]
  severity_context?: string
  confidence?: string
  evidence_strength?: string
  redaction_status?: string
  secret_detection_status?: string
  evidence_quality_score?: number
  evidence_quality_label?: string
  safe_summary?: string
  redacted_request_summary?: string
  redacted_response_summary?: string
  safe_observed_value?: string
  timeline_events?: ApiRecord[]
  limitations?: string[]
  [key: string]: unknown
}

export interface EvidenceVaultResponse {
  evidence_items?: EvidenceVaultItem[]
  evidence_vault_item?: EvidenceVaultItem
  count?: number
  redacted_text?: string
  redaction_check?: ApiRecord
  evidence_quality?: ApiRecord
  timeline_events?: ApiRecord[]
  export_allowed?: boolean
  export_paths?: Record<string, string>
  blocked_evidence?: ApiRecord[]
  [key: string]: unknown
}

export interface ProfessionalFinding {
  finding_id?: string
  title?: string
  status?: string
  finding_type?: string
  owasp_categories?: string[]
  affected_targets?: string[]
  affected_urls?: string[]
  affected_components?: string[]
  affected_parameters?: string[]
  severity?: string
  risk_score?: number
  confidence?: string
  evidence_strength?: string
  validation_status?: string
  executive_summary?: string
  technical_summary?: string
  business_impact?: string
  technical_impact?: string
  affected_roles?: string[]
  affected_workflows?: string[]
  evidence_references?: string[]
  evidence_quality_summary?: ApiRecord
  remediation?: string
  developer_guidance?: string
  validation_guidance?: string
  retest_status?: string
  retest_notes?: string
  risk_acceptance?: ApiRecord | null
  limitations?: string[]
  safe_testing_statement?: string
  source_modules?: string[]
  tags?: string[]
  warnings?: string[]
  risk_rating?: ApiRecord
  export_safety_status?: ApiRecord
  [key: string]: unknown
}

export interface ProfessionalFindingRequest {
  finding_id?: string
  title: string
  status?: string
  finding_type?: string
  owasp_categories?: string[]
  affected_targets?: string[]
  affected_urls?: string[]
  affected_components?: string[]
  affected_parameters?: string[]
  severity?: string
  confidence?: string
  evidence_strength?: string
  validation_status?: string
  executive_summary?: string
  technical_summary?: string
  business_impact?: string
  technical_impact?: string
  affected_roles?: string[]
  affected_workflows?: string[]
  remediation?: string
  developer_guidance?: string
  validation_guidance?: string
  retest_status?: string
  retest_notes?: string
  evidence_references?: string[]
  limitations?: string[]
  tags?: string[]
}

export interface ProfessionalFindingsResponse {
  finding?: ProfessionalFinding
  findings?: ProfessionalFinding[]
  total?: number
  path?: string | null
  [key: string]: unknown
}

export interface ComposedReport {
  report_id?: string
  title?: string
  target?: string
  client_or_project_name?: string
  assessment_type?: string
  report_status?: string
  generated_at?: string
  executive_summary?: ApiRecord
  risk_overview?: ApiRecord
  findings?: ProfessionalFinding[]
  evidence_summary?: ApiRecord
  owasp_summary?: ApiRecord
  retest_summary?: ApiRecord
  risk_acceptance_summary?: ApiRecord
  remediation_roadmap?: ApiRecord
  export_paths?: Record<string, string>
  export_safety_status?: string
  [key: string]: unknown
}

export interface ReportComposeRequest {
  title: string
  target?: string
  client_or_project_name?: string
  assessment_type?: string
  report_status?: string
  findings?: ProfessionalFinding[]
  findings_file?: string
  scope_summary?: string
  methodology_summary?: string
  markdown?: boolean
  html?: boolean
  json?: boolean
}

export interface ReportComposerResponse {
  report?: ComposedReport
  export_paths?: Record<string, string>
  export_allowed?: boolean
  status?: string
  checked_findings?: ApiRecord[]
  blocked_findings?: ApiRecord[]
  [key: string]: unknown
}

export interface DemoDashboardSummary {
  assets_assessed?: number
  findings?: number
  owasp_categories_covered?: number
  evidence_items?: number
  reports_generated?: number
  manual_plans?: number
  badge?: string
  [key: string]: unknown
}

export interface DemoDataset {
  demo_mode?: boolean
  dataset_name?: string
  generated_at?: string
  target?: string
  safe_testing_statement?: string
  dashboard_summary?: DemoDashboardSummary
  owasp_assessment?: ApiRecord
  evidence_vault?: ApiRecord
  findings?: ProfessionalFinding[]
  authenticated_assessment?: ApiRecord
  role_mapping?: ApiRecord
  access_tests?: ApiRecord
  replay_plans?: ApiRecord
  business_logic?: ApiRecord
  report_composer?: ApiRecord
  feature_tour?: ApiRecord[]
  walkthrough?: string[]
  [key: string]: unknown
}

export interface DemoDatasetResponse {
  demo_dataset?: DemoDataset
  simulated?: boolean
  [key: string]: unknown
}

export interface DemoStatusResponse {
  available?: boolean
  mode?: string
  dataset?: string
  local_demo_only?: boolean
  safe_testing_statement?: string
  [key: string]: unknown
}

export interface EvidenceCreateRequest {
  title: string
  evidence_type?: string
  source_module?: string
  safe_summary: string
  related_owasp_categories?: string[]
  related_url?: string
  related_target?: string
  confidence?: string
  evidence_strength?: string
}
