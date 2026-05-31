import { useEffect, useMemo, useState } from 'react'
import { getOWASPCategories, mapOWASP } from '../api/client'
import type { JobResultResponse, OWASPCategory, OWASPMapResponse, OWASPMappedItem, OWASPSummary } from '../types/api'
import { ErrorAlert } from './ErrorAlert'
import { OWASPCategoryTable } from './OWASPCategoryTable'
import { OWASPCoverageChart } from './OWASPCoverageChart'
import { OWASPFindingList } from './OWASPFindingList'
import { OWASPSummaryCards } from './OWASPSummaryCards'

interface OWASPMappingViewProps {
  apiOnline: boolean
  demoMode?: boolean
  jobResult?: JobResultResponse | null
}

const demoCategories: OWASPCategory[] = [
  { owasp_id: 'A01:2025', name: 'Broken Access Control', short_description: 'Access control indicators.' },
  { owasp_id: 'A02:2025', name: 'Security Misconfiguration', short_description: 'Configuration indicators.' },
  { owasp_id: 'A03:2025', name: 'Software Supply Chain Failures', short_description: 'Component indicators.' },
  { owasp_id: 'A04:2025', name: 'Cryptographic Failures', short_description: 'Transport and sensitive data indicators.' },
  { owasp_id: 'A05:2025', name: 'Injection', short_description: 'Input indicators.' },
  { owasp_id: 'A06:2025', name: 'Insecure Design', short_description: 'Design review indicators.' },
  { owasp_id: 'A07:2025', name: 'Authentication Failures', short_description: 'Authentication indicators.' },
  { owasp_id: 'A08:2025', name: 'Software or Data Integrity Failures', short_description: 'Integrity indicators.' },
  { owasp_id: 'A09:2025', name: 'Security Logging & Alerting Failures', short_description: 'Logging indicators.' },
  { owasp_id: 'A10:2025', name: 'Mishandling of Exceptional Conditions', short_description: 'Error handling indicators.' },
]

const demoSummary: OWASPSummary = {
  enabled: true,
  version: '2025',
  mapped_findings_count: 3,
  unmapped_findings_count: 5,
  manual_validation_required_count: 4,
  category_counts: { 'A01:2025': 1, 'A02:2025': 2, 'A03:2025': 0, 'A04:2025': 1, 'A05:2025': 1 },
  category_confidence_counts: { 'A02:2025': { High: 0, Medium: 2, Low: 0 } },
  highest_signal_categories: [{ owasp_id: 'A02:2025', owasp_name: 'Security Misconfiguration', count: 2 }],
  coverage_gaps: [{ owasp_id: 'A03:2025', owasp_name: 'Software Supply Chain Failures', explanation: 'No indicators were mapped. This does not mean no vulnerability exists.' }],
}

const demoItems: OWASPMappedItem[] = [
  {
    item_type: 'finding',
    title: 'Missing Security Header',
    source: 'web_header_audit',
    owasp_id: 'A02:2025',
    owasp_name: 'Security Misconfiguration',
    confidence: 'Medium',
    mapping_reason: 'Finding source maps to a security misconfiguration indicator.',
    manual_validation_required: true,
  },
]

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'OWASP mapping request failed.'
}

export function OWASPMappingView({ apiOnline, demoMode = false, jobResult }: OWASPMappingViewProps) {
  const [categories, setCategories] = useState<OWASPCategory[]>(demoMode ? demoCategories : [])
  const [mapped, setMapped] = useState<OWASPMapResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (demoMode) {
      setCategories(demoCategories)
      setMapped({ owasp_top10_summary: demoSummary, owasp_top10_mapped_items: demoItems })
      return
    }
    if (!apiOnline) return
    getOWASPCategories()
      .then((response) => setCategories(response.categories))
      .catch((caught) => setError(errorMessage(caught)))
  }, [apiOnline, demoMode])

  const resultPayload = jobResult?.result as Record<string, unknown> | null | undefined
  const existingSummary = resultPayload?.owasp_top10_summary as OWASPSummary | undefined
  const existingItems = resultPayload?.owasp_top10_mapped_items as OWASPMappedItem[] | undefined

  const summary = existingSummary || mapped?.owasp_top10_summary
  const items = existingItems || mapped?.owasp_top10_mapped_items || []
  const gaps = summary?.coverage_gaps || []

  const canMapSelectedResult = useMemo(() => Boolean(resultPayload && !existingSummary), [existingSummary, resultPayload])

  async function mapSelectedResult() {
    if (!resultPayload) return
    setLoading(true)
    setError(null)
    try {
      setMapped(await mapOWASP({
        findings: (resultPayload.findings as []) || [],
        endpoint_results: (resultPayload.endpoint_results as []) || [],
        parameter_results: (resultPayload.parameter_results as []) || [],
      }))
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="content-grid">
      <article className="panel panel--wide">
        <div className="panel-heading">
          <div>
            <h2>OWASP Top 10 Indicators</h2>
            <p>Indicator mapping for selected job results. No indicator does not mean no vulnerability.</p>
          </div>
          <button className="secondary-button" type="button" disabled={!canMapSelectedResult || loading} onClick={() => void mapSelectedResult()}>
            {loading ? 'Mapping...' : 'Map Selected Result'}
          </button>
        </div>
        <ErrorAlert message={error} />
        <OWASPSummaryCards summary={summary} />
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>Coverage Chart</h2>
          <p>Counts by OWASP Top 10:2025 indicator category.</p>
        </div>
        <OWASPCoverageChart summary={summary} />
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>Category Coverage</h2>
          <p>Status values are indicators, not confirmed OWASP vulnerabilities.</p>
        </div>
        <OWASPCategoryTable categories={categories} summary={summary} />
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>Mapped Findings And Candidates</h2>
          <p>Manual validation required where shown.</p>
        </div>
        <OWASPFindingList items={items} />
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>Coverage Gaps</h2>
          <p>No indicator does not mean no vulnerability.</p>
        </div>
        {!gaps.length ? <div className="panel-message">No coverage gaps to show for the selected mapped result.</div> : (
          <div className="table-shell">
            <table>
              <thead><tr><th>Category</th><th>Explanation</th></tr></thead>
              <tbody>
                {gaps.map((gap) => <tr key={gap.owasp_id}><td>{gap.owasp_id} {gap.owasp_name}</td><td>{gap.explanation}</td></tr>)}
              </tbody>
            </table>
          </div>
        )}
      </article>
    </section>
  )
}
