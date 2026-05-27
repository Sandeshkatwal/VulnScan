import type { Finding } from '../types/api'

export function formatValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return 'Not available'
  if (Array.isArray(value)) return value.length ? value.map(String).join(', ') : 'Not available'
  if (typeof value === 'boolean') return value ? 'Yes' : 'No'
  return String(value)
}

export function getCve(finding: Finding): string {
  const direct = finding.cve
  if (direct) return String(direct)
  const details = finding.evidence_details
  const value = details?.cve || details?.cve_id || details?.cves
  return formatValue(value)
}

export function getCvss(finding: Finding): string {
  return formatValue(finding.cvss_score ?? finding.evidence_details?.cvss_score)
}

export function getEpss(finding: Finding): string {
  return formatValue(finding.epss_score ?? finding.evidence_details?.epss_score)
}

export function getExploitAvailable(finding: Finding): boolean | null {
  const value = finding.exploit_available ?? finding.evidence_details?.exploit_available
  if (typeof value === 'boolean') return value
  if (typeof value === 'string') return value.toLowerCase() === 'true'
  return null
}

export function findingSearchText(finding: Finding): string {
  return [
    finding.title,
    finding.source,
    finding.category,
    finding.evidence,
    finding.recommendation,
    getCve(finding),
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase()
}
