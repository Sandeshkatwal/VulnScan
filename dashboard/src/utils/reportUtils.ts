import type { ApiRecord, FindingsResponse, JobResultResponse, JobSummary, ReportMetadata, ReportSummary } from '../types/api'

export function isRecord(value: unknown): value is ApiRecord {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value))
}

export function getResultPayload(result?: JobResultResponse | null): ApiRecord {
  return isRecord(result?.result) ? result.result : {}
}

function numberFrom(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value)
    if (Number.isFinite(parsed)) return parsed
  }
  return null
}

export function getFindingsCount(job: JobSummary, findings?: FindingsResponse | null): number | null {
  const summary = isRecord(job.result_summary) ? job.result_summary : {}
  const fromSummary = numberFrom(summary.total_findings ?? summary.findings_count ?? summary.total_vulnerabilities)
  if (fromSummary !== null) return fromSummary
  const fromPagination = numberFrom(findings?.pagination?.total)
  if (fromPagination !== null) return fromPagination
  return findings?.findings?.length ?? null
}

function hasEnabledSection(payload: ApiRecord, key: string): boolean {
  const section = payload[key]
  if (!isRecord(section)) return false
  if (section.enabled === false) return false
  return Object.keys(section).length > 0
}

export function buildReportSummary(job: JobSummary, result?: JobResultResponse | null, findings?: FindingsResponse | null): ReportSummary {
  const payload = getResultPayload(result)
  return {
    job_id: job.job_id,
    scan_id: job.scan_id,
    target: job.target,
    status: job.status,
    result_path: job.result_path,
    html_report_path: job.html_report_path,
    completed_at: job.completed_at,
    duration_seconds: job.duration_seconds,
    findings_count: getFindingsCount(job, findings),
    has_json_report: Boolean(job.result_path),
    has_html_report: Boolean(job.html_report_path),
    has_fix_first_dashboard: hasEnabledSection(payload, 'fix_first_dashboard'),
    has_trend_data: hasEnabledSection(payload, 'prioritisation_trends'),
    has_vuln_intel: hasEnabledSection(payload, 'vulnerability_intelligence'),
    has_web_dast: hasEnabledSection(payload, 'web_dast_summary'),
  }
}

export function buildReportMetadata(job: JobSummary, result?: JobResultResponse | null, findings?: FindingsResponse | null): ReportMetadata {
  const payload = getResultPayload(result)
  return {
    report_summary: buildReportSummary(job, result, findings),
    prioritisation_summary: isRecord(payload.prioritisation_summary) ? payload.prioritisation_summary : null,
    fix_first_dashboard: isRecord(payload.fix_first_dashboard) ? payload.fix_first_dashboard : null,
    prioritisation_trends: isRecord(payload.prioritisation_trends) ? payload.prioritisation_trends : null,
    vulnerability_intelligence: isRecord(payload.vulnerability_intelligence) ? payload.vulnerability_intelligence : null,
    web_dast_summary: isRecord(payload.web_dast_summary) ? payload.web_dast_summary : null,
    asset_context: isRecord(payload.asset_context) ? payload.asset_context : null,
  }
}

export function reportProducingJobs(jobs: JobSummary[]): JobSummary[] {
  return jobs.filter((job) => job.result_path || job.html_report_path)
}

export function hasReportFeature(job: JobSummary, key: string): boolean | null {
  const summary = isRecord(job.result_summary) ? job.result_summary : {}
  if (typeof summary[key] === 'boolean') return summary[key]
  if (summary[key] !== undefined && summary[key] !== null) return true
  return null
}
