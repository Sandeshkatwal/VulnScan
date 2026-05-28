import type { Finding } from '../types/api'
import { getCve, getExploitAvailable } from './format'

export type SeverityBucket = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational'
export type PriorityBucket = 'Fix First' | 'Fix Soon' | 'Monitor' | 'Informational' | 'Unknown'

const severityOrder: Record<SeverityBucket, number> = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Informational: 1,
}

const severityBuckets: SeverityBucket[] = ['Critical', 'High', 'Medium', 'Low', 'Informational']
const priorityBuckets: PriorityBucket[] = ['Fix First', 'Fix Soon', 'Monitor', 'Informational', 'Unknown']

export function normaliseSeverity(severity: unknown): SeverityBucket {
  const text = String(severity ?? '').trim().toLowerCase()
  if (text === 'critical') return 'Critical'
  if (text === 'high') return 'High'
  if (text === 'medium') return 'Medium'
  if (text === 'low') return 'Low'
  return 'Informational'
}

export function normalisePriority(priorityLabel: unknown): PriorityBucket {
  const text = String(priorityLabel ?? '').trim().toLowerCase()
  if (text === 'fix first') return 'Fix First'
  if (text === 'fix soon' || text === 'schedule') return 'Fix Soon'
  if (text === 'monitor') return 'Monitor'
  if (text === 'informational') return 'Informational'
  return 'Unknown'
}

export function toNumber(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value)
    if (Number.isFinite(parsed)) return parsed
  }
  return null
}

function emptyCounts<T extends string>(keys: T[]): Record<T, number> {
  return Object.fromEntries(keys.map((key) => [key, 0])) as Record<T, number>
}

export function countBySeverity(findings: Finding[]): Record<SeverityBucket, number> {
  const counts = emptyCounts(severityBuckets)
  findings.forEach((finding) => {
    counts[normaliseSeverity(finding.severity)] += 1
  })
  return counts
}

export function countByPriority(findings: Finding[]): Record<PriorityBucket, number> {
  const counts = emptyCounts(priorityBuckets)
  findings.forEach((finding) => {
    counts[normalisePriority(finding.priority_label)] += 1
  })
  return counts
}

export function countBySource(findings: Finding[], limit = 8): Record<string, number> {
  const raw = new Map<string, number>()
  findings.forEach((finding) => {
    const source = String(finding.source || 'other').trim() || 'other'
    raw.set(source, (raw.get(source) || 0) + 1)
  })

  const sorted = [...raw.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
  const top = sorted.slice(0, limit)
  const remaining = sorted.slice(limit).reduce((sum, [, count]) => sum + count, 0)
  const result = Object.fromEntries(top)
  if (remaining > 0) result.Other = remaining
  return result
}

function severityRank(finding: Finding): number {
  return severityOrder[normaliseSeverity(finding.severity)]
}

export function getTopRiskFindings(findings: Finding[], limit = 5): Finding[] {
  return [...findings]
    .sort((left, right) => {
      const leftPriority = toNumber(left.priority_score)
      const rightPriority = toNumber(right.priority_score)
      if (leftPriority !== null || rightPriority !== null) {
        return (rightPriority ?? -1) - (leftPriority ?? -1)
      }

      const leftRisk = toNumber(left.risk_score)
      const rightRisk = toNumber(right.risk_score)
      if (leftRisk !== null || rightRisk !== null) {
        return (rightRisk ?? -1) - (leftRisk ?? -1)
      }

      return severityRank(right) - severityRank(left)
    })
    .slice(0, limit)
}

export function getHighestPriorityScore(findings: Finding[]): number | null {
  const scores = findings.map((finding) => toNumber(finding.priority_score)).filter((score): score is number => score !== null)
  return scores.length ? Math.max(...scores) : null
}

export function getHighestRiskScore(findings: Finding[]): number | null {
  const scores = findings.map((finding) => toNumber(finding.risk_score)).filter((score): score is number => score !== null)
  return scores.length ? Math.max(...scores) : null
}

export function countCveFindings(findings: Finding[]): number {
  return findings.filter((finding) => getCve(finding) !== 'Not available').length
}

export function countExploitMetadata(findings: Finding[]): number {
  return findings.filter((finding) => getExploitAvailable(finding) === true).length
}
