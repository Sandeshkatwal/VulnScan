import type { DemoDataset } from '../types/api'

export const portfolioDemoDataset: DemoDataset = {
  demo_mode: true,
  dataset_name: 'Safe Demo Dataset',
  generated_at: 'Demo Date',
  target: 'https://demo.local',
  safe_testing_statement: 'Portfolio Demo Mode uses simulated redacted data only. No real target was scanned and no live requests were sent.',
  dashboard_summary: {
    assets_assessed: 3,
    findings: 6,
    owasp_categories_covered: 10,
    evidence_items: 6,
    reports_generated: 1,
    manual_plans: 4,
    badge: 'Portfolio Demo Mode — simulated redacted data.',
  },
  findings: [
    { finding_id: 'demo-finding-001', title: 'Simulated Missing Content-Security-Policy Header', severity: 'Low', confidence: 'Low', validation_status: 'manual_validation_required', status: 'draft', owasp_categories: ['A02:2025'], evidence_references: ['demo-evidence-001'], remediation: 'Harden browser security headers and validate policy compatibility.', retest_status: 'not_retested' },
    { finding_id: 'demo-finding-002', title: 'Simulated Session Cookie Missing HttpOnly Attribute', severity: 'Medium', confidence: 'Low', validation_status: 'manual_validation_required', status: 'draft', owasp_categories: ['A07:2025'], evidence_references: ['demo-evidence-002'], remediation: 'Harden session cookie attributes after application testing.', retest_status: 'not_retested' },
    { finding_id: 'demo-finding-003', title: 'Simulated IDOR Candidate Requiring Manual Validation', severity: 'Medium', confidence: 'Low', validation_status: 'manual_validation_required', status: 'draft', owasp_categories: ['A01:2025'], evidence_references: ['demo-evidence-003'], remediation: 'Enforce server-side authorization and object ownership checks.', retest_status: 'not_retested' },
  ],
  owasp_assessment: {
    coverage_matrix: ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10'].map((category) => ({ category, status: 'Simulated indicator coverage, manual validation required', evidence_count: 1, manual_validation_required: true, simulated: true })),
  },
  evidence_vault: {
    evidence_vault_items: [
      { evidence_id: 'demo-evidence-001', title: 'Redacted Demo Evidence: CSP header review', redaction_status: 'redacted', secret_detection_status: 'passed', evidence_quality_score: 82 },
      { evidence_id: 'demo-evidence-002', title: 'Redacted Demo Evidence: Cookie attribute review', redaction_status: 'redacted', secret_detection_status: 'passed', evidence_quality_score: 82 },
      { evidence_id: 'demo-evidence-003', title: 'Redacted Demo Evidence: Role ownership review', redaction_status: 'redacted', secret_detection_status: 'passed', evidence_quality_score: 82 },
    ],
  },
  authenticated_assessment: { authenticated_crawl_summary: { pages_observed: 12, boundary_events: 2, simulated: true }, safe_note: 'Redacted demo session profile only.' },
  role_mapping: { roles: ['anonymous', 'standard_user', 'support_user', 'admin_reviewer'], simulated: true },
  access_tests: { plans: [{ test_plan_id: 'demo-access-plan-001', expected: 'denied', status: 'manual_validation_required' }] },
  replay_plans: { plans: [{ replay_plan_id: 'demo-replay-plan-001', parameter: 'user_id', intent: 'object_ownership_review' }] },
  business_logic: { plans: [{ review_plan_id: 'demo-business-plan-001', workflow: 'checkout', status: 'manual_validation_required' }] },
  report_composer: { draft_title: 'VulScan Portfolio Demo Report', export_formats: ['markdown', 'html', 'json'], simulated: true },
  feature_tour: [
    { title: 'Dashboard Overview', module: 'Dashboard Home', explanation: 'Review portfolio summary metrics and module readiness.', safe_note: 'Uses simulated redacted data.' },
    { title: 'Review OWASP matrix', module: 'OWASP Report', explanation: 'Inspect A01-A10 simulated coverage.', safe_note: 'Indicators require manual validation.' },
    { title: 'Use Evidence Vault', module: 'Evidence Vault', explanation: 'Show Redacted Demo Evidence and quality status.', safe_note: 'No raw evidence export.' },
    { title: 'Compose report', module: 'Report Composer', explanation: 'Generate a Demo Report.', safe_note: 'Export safety checks apply.' },
  ],
  walkthrough: [
    'Dashboard Home, 30 seconds: introduce VulScan as an OWASP-focused assessment and reporting platform.',
    'OWASP Report Matrix, 1 minute: show simulated A01-A10 coverage and manual validation status.',
    'Evidence Vault, 1 minute: show Redacted Demo Evidence, quality score, and safety checks.',
    'Finding Builder and Report Composer, 1 minute: compose careful Technical Findings and a Demo Report.',
  ],
}

