import { useEffect, useMemo, useState } from 'react'
import { buildOWASPAssessment, buildOWASPReport, downloadOWASPReport, getOWASPCategories, getOWASPAssessmentRules, mapOWASP } from '../api/client'
import type {
  JobResultResponse,
  OWASPAssessmentResponse,
  OWASPAssessmentSummary,
  OWASPCategory,
  OWASPCategoryResult,
  OWASPCoverageGap,
  OWASPEvidenceItem,
  OWASPAssessmentReport,
  OWASPDeveloperRecommendation,
  OWASPManualValidationItem,
  OWASPMapResponse,
  OWASPMappedItem,
  OWASPSummary,
  A01AccessControlEvidenceItem,
  A01AccessControlSummary,
  A03SupplyChainEvidenceItem,
  A03SupplyChainSummary,
  A08IntegrityEvidenceItem,
  A08IntegritySummary,
  A04CryptoEvidenceItem,
  A04CryptoSummary,
  A04TlsMetadata,
  A07AuthenticationEvidenceItem,
  A07AuthenticationSummary,
  A05InjectionEvidenceItem,
  A05InjectionSummary,
  A10ErrorHandlingEvidenceItem,
  A10ErrorHandlingSummary,
} from '../types/api'
import { A01AccessControlView } from './A01AccessControlView'
import { A03SupplyChainView } from './A03SupplyChainView'
import { A08IntegrityView } from './A08IntegrityView'
import { A04CryptoView } from './A04CryptoView'
import { A05InjectionView } from './A05InjectionView'
import { A07AuthenticationView } from './A07AuthenticationView'
import { A10ErrorHandlingView } from './A10ErrorHandlingView'
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

const demoAssessment: OWASPAssessmentResponse = {
  owasp_assessment_summary: {
    enabled: true,
    owasp_version: '2025',
    target: 'demo-web.local',
    total_evidence_items: 5,
    confirmed_findings_count: 0,
    strong_indicators_count: 2,
    weak_indicators_count: 3,
    manual_validation_required_count: 4,
    categories_assessed_count: 3,
    categories_with_indicators_count: 4,
    coverage_gaps_count: 6,
    assessment_quality_score: 42,
    assessment_quality_label: 'Developing',
  },
  owasp_category_results: [
    { owasp_id: 'A01:2025', name: 'Broken Access Control', assessment_status: 'needs_manual_validation', coverage_status: 'partially_assessed', evidence_count: 1, highest_confidence: 'Low', manual_validation_required_count: 1, recommendation_themes: ['Validate object ownership.'], limitations: 'Access-control issues usually require authenticated manual validation.' },
    { owasp_id: 'A02:2025', name: 'Security Misconfiguration', assessment_status: 'detected_indicator', coverage_status: 'assessed', evidence_count: 2, highest_confidence: 'Medium', strong_indicator_count: 1, weak_indicator_count: 1, recommendation_themes: ['Harden HTTP response headers.'], limitations: 'Configuration indicators may require environment context.' },
    { owasp_id: 'A05:2025', name: 'Injection', assessment_status: 'needs_manual_validation', coverage_status: 'partially_assessed', evidence_count: 1, highest_confidence: 'Medium', strong_indicator_count: 1, manual_validation_required_count: 1, recommendation_themes: ['Apply contextual output encoding.'], limitations: 'Input indicators do not confirm injection without controlled manual validation.' },
  ],
  owasp_evidence_items: [
    { title: 'Missing Content Security Policy', source: 'web_header_audit', affected_url: 'https://demo-web.local/', owasp_id: 'A02:2025', owasp_name: 'Security Misconfiguration', evidence_strength: 'strong_indicator', confidence: 'Medium', assessment_status: 'detected_indicator', manual_validation_required: false },
    { title: 'Parameter indicator: id', source: 'parameter_intelligence', affected_url: 'https://demo-web.local/account?id=1', affected_parameter: 'id', owasp_id: 'A01:2025', owasp_name: 'Broken Access Control', evidence_strength: 'weak_indicator', confidence: 'Low', assessment_status: 'needs_manual_validation', manual_validation_required: true },
    { title: 'Reflected input observation', source: 'safe_active_validation', affected_url: 'https://demo-web.local/search?q=test', affected_parameter: 'q', owasp_id: 'A05:2025', owasp_name: 'Injection', evidence_strength: 'strong_indicator', confidence: 'Medium', assessment_status: 'needs_manual_validation', manual_validation_required: true },
  ],
  owasp_coverage_gaps: [
    { owasp_id: 'A09:2025', owasp_name: 'Security Logging & Alerting Failures', coverage_status: 'manual_only', explanation: 'No indicator found does not mean the category is secure. It may mean the category was not assessed or requires authenticated/manual testing.' },
  ],
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'OWASP mapping request failed.'
}

export function OWASPMappingView({ apiOnline, demoMode = false, jobResult }: OWASPMappingViewProps) {
  const [categories, setCategories] = useState<OWASPCategory[]>(demoMode ? demoCategories : [])
  const [mapped, setMapped] = useState<OWASPMapResponse | null>(null)
  const [assessment, setAssessment] = useState<OWASPAssessmentResponse | null>(demoMode ? demoAssessment : null)
  const [loading, setLoading] = useState(false)
  const [assessmentLoading, setAssessmentLoading] = useState(false)
  const [reportLoading, setReportLoading] = useState(false)
  const [reportMessage, setReportMessage] = useState<string | null>(null)
  const [localChecklistState, setLocalChecklistState] = useState<Record<string, string>>({})
  const [evidenceFilter, setEvidenceFilter] = useState({ category: 'all', strength: 'all', confidence: 'all', source: 'all' })
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (demoMode) {
      setCategories(demoCategories)
      setMapped({ owasp_top10_summary: demoSummary, owasp_top10_mapped_items: demoItems })
      setAssessment(demoAssessment)
      return
    }
    if (!apiOnline) return
    Promise.all([getOWASPCategories(), getOWASPAssessmentRules()])
      .then(([mappingResponse, rulesResponse]) => setCategories(rulesResponse.categories || mappingResponse.categories))
      .catch((caught) => setError(errorMessage(caught)))
  }, [apiOnline, demoMode])

  const resultPayload = jobResult?.result as Record<string, unknown> | null | undefined
  const existingSummary = resultPayload?.owasp_top10_summary as OWASPSummary | undefined
  const existingItems = resultPayload?.owasp_top10_mapped_items as OWASPMappedItem[] | undefined
  const existingAssessmentSummary = resultPayload?.owasp_assessment_summary as OWASPAssessmentSummary | undefined
  const existingAssessmentReport = resultPayload?.owasp_assessment_report as OWASPAssessmentReport | undefined
  const existingCategoryResults = resultPayload?.owasp_category_results as OWASPCategoryResult[] | undefined
  const existingEvidenceItems = resultPayload?.owasp_evidence_items as OWASPEvidenceItem[] | undefined
  const existingCoverageMatrix = resultPayload?.owasp_coverage_matrix as OWASPCategoryResult[] | undefined
  const existingChecklist = resultPayload?.owasp_manual_validation_checklist as OWASPManualValidationItem[] | undefined
  const existingRecommendations = resultPayload?.owasp_developer_recommendations as OWASPDeveloperRecommendation[] | undefined
  const existingCoverageGaps = resultPayload?.owasp_coverage_gaps as OWASPCoverageGap[] | undefined
  const a01Summary = resultPayload?.a01_access_control_summary as A01AccessControlSummary | undefined
  const a01Evidence = (resultPayload?.a01_access_control_evidence as A01AccessControlEvidenceItem[] | undefined) || []
  const a03Summary = resultPayload?.a03_supply_chain_summary as A03SupplyChainSummary | undefined
  const a03Evidence = (resultPayload?.a03_supply_chain_evidence as A03SupplyChainEvidenceItem[] | undefined) || []
  const a08Summary = resultPayload?.a08_integrity_summary as A08IntegritySummary | undefined
  const a08Evidence = (resultPayload?.a08_integrity_evidence as A08IntegrityEvidenceItem[] | undefined) || []
  const a04Summary = resultPayload?.a04_crypto_summary as A04CryptoSummary | undefined
  const a04Evidence = (resultPayload?.a04_crypto_evidence as A04CryptoEvidenceItem[] | undefined) || []
  const a04TlsMetadata = (resultPayload?.a04_tls_metadata as A04TlsMetadata[] | undefined) || []
  const a07Summary = resultPayload?.a07_authentication_summary as A07AuthenticationSummary | undefined
  const a07Evidence = (resultPayload?.a07_authentication_evidence as A07AuthenticationEvidenceItem[] | undefined) || []
  const a05Summary = resultPayload?.a05_injection_summary as A05InjectionSummary | undefined
  const a05Evidence = (resultPayload?.a05_injection_evidence as A05InjectionEvidenceItem[] | undefined) || []
  const a10Summary = resultPayload?.a10_error_handling_summary as A10ErrorHandlingSummary | undefined
  const a10Evidence = (resultPayload?.a10_error_handling_evidence as A10ErrorHandlingEvidenceItem[] | undefined) || []

  const summary = existingSummary || mapped?.owasp_top10_summary
  const items = existingItems || mapped?.owasp_top10_mapped_items || []
  const gaps = summary?.coverage_gaps || []
  const assessmentSummary = existingAssessmentSummary || assessment?.owasp_assessment_summary
  const categoryResults = existingCategoryResults || assessment?.owasp_category_results || []
  const evidenceItems = existingEvidenceItems || assessment?.owasp_evidence_items || []
  const coverageGaps = existingCoverageGaps || assessment?.owasp_coverage_gaps || []
  const coverageMatrix = existingCoverageMatrix || assessment?.owasp_coverage_matrix || existingAssessmentReport?.category_results || assessment?.owasp_assessment_report?.category_results || categoryResults
  const checklist = existingChecklist || assessment?.owasp_manual_validation_checklist || existingAssessmentReport?.manual_validation_summary?.checklist || assessment?.owasp_assessment_report?.manual_validation_summary?.checklist || []
  const recommendations = existingRecommendations || assessment?.owasp_developer_recommendations || existingAssessmentReport?.developer_recommendations || assessment?.owasp_assessment_report?.developer_recommendations || []
  const owaspReport = existingAssessmentReport || assessment?.owasp_assessment_report || buildLocalOWASPReport(assessmentSummary, coverageMatrix, evidenceItems, coverageGaps, checklist, recommendations)
  const filteredEvidenceItems = evidenceItems.filter((item) => {
    return (evidenceFilter.category === 'all' || item.owasp_id === evidenceFilter.category)
      && (evidenceFilter.strength === 'all' || item.evidence_strength === evidenceFilter.strength)
      && (evidenceFilter.confidence === 'all' || item.confidence === evidenceFilter.confidence)
      && (evidenceFilter.source === 'all' || item.source === evidenceFilter.source)
  })

  const canMapSelectedResult = useMemo(() => Boolean(resultPayload && !existingSummary), [existingSummary, resultPayload])
  const canBuildAssessment = useMemo(() => Boolean(resultPayload && !existingAssessmentSummary), [existingAssessmentSummary, resultPayload])

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

  async function buildSelectedAssessment() {
    if (!resultPayload) return
    setAssessmentLoading(true)
    setError(null)
    try {
      setAssessment(await buildOWASPAssessment({
        findings: (resultPayload.findings as []) || [],
        endpoint_results: (resultPayload.endpoint_results as []) || [],
        parameter_results: (resultPayload.parameter_results as []) || [],
        safe_validation_results: (resultPayload.safe_active_validation_results as []) || [],
        evidence_records: (resultPayload.evidence_records as []) || [],
      }))
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setAssessmentLoading(false)
    }
  }

  async function exportOWASPReport() {
    setReportLoading(true)
    setReportMessage(null)
    setError(null)
    try {
      const response = await buildOWASPReport({
        target: String(resultPayload?.target || resultPayload?.host || assessmentSummary?.target || 'demo-web.local'),
        owasp_assessment_summary: assessmentSummary,
        owasp_category_results: coverageMatrix,
        owasp_evidence_items: evidenceItems,
      })
      const reportId = response.owasp_assessment_report?.report_id
      setReportMessage(response.markdown_report_path ? `Markdown report generated: ${response.markdown_report_path}` : 'Markdown report generated.')
      if (reportId) {
        await downloadOWASPReport(reportId, `${reportId}.md`)
      }
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setReportLoading(false)
    }
  }

  return (
    <section className="content-grid">
      <article className="panel panel--wide">
        <div className="panel-heading">
          <div>
            <h2>OWASP Assessment</h2>
            <p>OWASP Top 10:2025 category-level evidence, confidence, coverage, and manual validation status.</p>
          </div>
          <button className="primary-button" type="button" disabled={!canBuildAssessment || assessmentLoading} onClick={() => void buildSelectedAssessment()}>
            {assessmentLoading ? 'Building...' : 'Build Assessment'}
          </button>
          <button className="secondary-button" type="button" disabled={!canMapSelectedResult || loading} onClick={() => void mapSelectedResult()}>
            {loading ? 'Mapping...' : 'Map Selected Result'}
          </button>
        </div>
        <ErrorAlert message={error} />
        <AssessmentSummaryCards summary={assessmentSummary} />
        <OWASPReportOverview report={owaspReport} />
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>OWASP Coverage Matrix</h2>
          <p>No indicator found does not mean the category is secure. It may mean the category was not assessed or requires authenticated/manual testing.</p>
        </div>
        <AssessmentCoverageMatrix categories={categories} categoryResults={coverageMatrix} />
      </article>

      <A01AccessControlView summary={a01Summary} evidence={a01Evidence} />

      <A03SupplyChainView summary={a03Summary} evidence={a03Evidence} />

      <A08IntegrityView summary={a08Summary} evidence={a08Evidence} />

      <A04CryptoView summary={a04Summary} evidence={a04Evidence} tlsMetadata={a04TlsMetadata} />

      <A05InjectionView summary={a05Summary} evidence={a05Evidence} />

      <A07AuthenticationView summary={a07Summary} evidence={a07Evidence} />

      <A10ErrorHandlingView summary={a10Summary} evidence={a10Evidence} />

      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>OWASP Category Results</h2>
          <p>Confirmed Finding appears only when supplied evidence already supports it.</p>
        </div>
        <CategoryResultCards categoryResults={categoryResults} />
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>OWASP Evidence</h2>
          <p>Evidence strength and indicator confidence are assessment inputs, not exploit results.</p>
        </div>
        <EvidenceStrengthSummary report={owaspReport} />
        <EvidenceFilters evidenceItems={evidenceItems} value={evidenceFilter} onChange={setEvidenceFilter} />
        <EvidenceTable evidenceItems={filteredEvidenceItems} />
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>Manual Validation Required</h2>
          <p>A01, A06, A09, and weak indicators often need authorised manual review.</p>
        </div>
        <ManualValidationPanel categoryResults={categoryResults} evidenceItems={evidenceItems} />
        <ManualValidationChecklist checklist={checklist} localState={localChecklistState} onChange={setLocalChecklistState} />
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>Developer Guidance</h2>
          <p>Category-specific remediation guidance and validation hints for developers.</p>
        </div>
        <DeveloperGuidance recommendations={recommendations} />
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>Coverage Gaps</h2>
          <p>No indicator found does not mean the category is secure. It may mean the category was not assessed or requires authenticated/manual testing.</p>
        </div>
        {!coverageGaps.length ? <div className="panel-message">No OWASP Assessment Engine coverage gaps to show.</div> : (
          <div className="table-shell">
            <table>
              <thead><tr><th>Category</th><th>Coverage</th><th>Explanation</th></tr></thead>
              <tbody>
                {coverageGaps.map((gap) => <tr key={gap.gap_title || gap.owasp_id}><td>{gap.category || gap.owasp_id} {gap.owasp_name}</td><td>{gap.coverage_status || 'coverage_gap'}</td><td>{gap.why_it_matters || gap.explanation}</td></tr>)}
              </tbody>
            </table>
          </div>
        )}
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>Export</h2>
          <p>Generate a Markdown-ready OWASP Assessment report through the local authenticated API.</p>
        </div>
        <OWASPReportExportPanel
          report={owaspReport}
          jsonPath={String(resultPayload?.result_path || '')}
          htmlPath={String(resultPayload?.html_report_path || '')}
          loading={reportLoading}
          message={reportMessage}
          disabled={!apiOnline && !demoMode}
          onExport={() => void exportOWASPReport()}
        />
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>OWASP Indicator Mapping</h2>
          <p>Legacy indicator mapping remains available for selected job results.</p>
        </div>
        <OWASPSummaryCards summary={summary} />
        <OWASPCoverageChart summary={summary} />
        <OWASPCategoryTable categories={categories} summary={summary} />
        <OWASPFindingList items={items} />
        {!!gaps.length && (
          <div className="table-shell">
            <table>
              <thead><tr><th>Category</th><th>Explanation</th></tr></thead>
              <tbody>{gaps.map((gap) => <tr key={gap.owasp_id}><td>{gap.owasp_id} {gap.owasp_name}</td><td>{gap.explanation}</td></tr>)}</tbody>
            </table>
          </div>
        )}
      </article>
    </section>
  )
}

function OWASPReportOverview({ report }: { report?: OWASPAssessmentReport }) {
  const executive = report?.executive_summary || {}
  const quality = report?.assessment_quality_score || {}
  const highest = (executive.highest_signal_categories as Array<Record<string, unknown>> | undefined) || []
  return (
    <div className="owasp-report-overview">
      <div className="report-summary-band">
        <div>
          <span>Executive summary</span>
          <p>{String(executive.summary_text || 'No unified OWASP Assessment report is available yet.')}</p>
        </div>
        <div className="quality-score">
          <strong>{Number(quality.score || 0)}</strong>
          <span>{String(quality.label || 'Limited Assessment')}</span>
        </div>
      </div>
      <div className="summary-grid">
        <div className="summary-card"><span>Coverage status</span><strong>{report?.overall_coverage_status || 'coverage_gap'}</strong></div>
        <div className="summary-card"><span>Manual validation</span><strong>{Number(executive.manual_validation_required_count || 0)}</strong></div>
        <div className="summary-card"><span>Coverage gaps</span><strong>{Number(executive.coverage_gaps_count || 0)}</strong></div>
        <div className="summary-card"><span>Report ID</span><strong>{report?.report_id || 'Not generated'}</strong></div>
      </div>
      {!!highest.length && (
        <div className="badge-row">
          {highest.map((item) => <span className="badge badge--owasp" key={String(item.category || item.owasp_id)}>{String(item.category || item.owasp_id)} {String(item.name || item.owasp_name || '')}</span>)}
        </div>
      )}
      <div className="panel-message">{String(quality.limitation || 'Assessment quality score reflects evidence coverage, not application security.')}</div>
    </div>
  )
}

function EvidenceStrengthSummary({ report }: { report?: OWASPAssessmentReport }) {
  const summary = report?.evidence_strength_summary || {}
  const cards: Array<[string, number]> = [
    ['Confirmed findings', Number(summary.confirmed_findings_count || 0)],
    ['Strong indicators', Number(summary.strong_indicators_count || 0)],
    ['Weak indicators', Number(summary.weak_indicators_count || 0)],
    ['Informational', Number(summary.informational_count || 0)],
    ['Manual validation', Number(summary.manual_validation_required_count || 0)],
  ]
  return <div className="summary-grid summary-grid--compact">{cards.map(([label, value]) => <div className="summary-card" key={label}><span>{label}</span><strong>{Number(value || 0)}</strong></div>)}</div>
}

function EvidenceFilters({
  evidenceItems,
  value,
  onChange,
}: {
  evidenceItems: OWASPEvidenceItem[]
  value: { category: string; strength: string; confidence: string; source: string }
  onChange: (value: { category: string; strength: string; confidence: string; source: string }) => void
}) {
  const categories = unique(evidenceItems.map((item) => item.owasp_id).filter(Boolean) as string[])
  const strengths = unique(evidenceItems.map((item) => item.evidence_strength).filter(Boolean) as string[])
  const confidences = unique(evidenceItems.map((item) => item.confidence).filter(Boolean) as string[])
  const sources = unique(evidenceItems.map((item) => item.source).filter(Boolean) as string[])
  return (
    <div className="filter-row">
      <SelectFilter label="Category" value={value.category} options={categories} onChange={(category) => onChange({ ...value, category })} />
      <SelectFilter label="Strength" value={value.strength} options={strengths} onChange={(strength) => onChange({ ...value, strength })} />
      <SelectFilter label="Confidence" value={value.confidence} options={confidences} onChange={(confidence) => onChange({ ...value, confidence })} />
      <SelectFilter label="Source" value={value.source} options={sources} onChange={(source) => onChange({ ...value, source })} />
    </div>
  )
}

function SelectFilter({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (value: string) => void }) {
  return (
    <label className="filter-control">
      <span>{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        <option value="all">All</option>
        {options.map((option) => <option value={option} key={option}>{option}</option>)}
      </select>
    </label>
  )
}

function ManualValidationChecklist({
  checklist,
  localState,
  onChange,
}: {
  checklist: OWASPManualValidationItem[]
  localState: Record<string, string>
  onChange: (value: Record<string, string>) => void
}) {
  if (!checklist.length) return <div className="panel-message">No consolidated manual validation checklist is available.</div>
  return (
    <div className="table-shell">
      <table>
        <thead><tr><th>Category</th><th>Item</th><th>Priority</th><th>Reason</th><th>Suggested Evidence</th><th>Status</th></tr></thead>
        <tbody>
          {checklist.map((item, index) => {
            const key = `${item.category}-${item.item}-${index}`
            const status = localState[key] || item.status || 'pending'
            return (
              <tr key={key}>
                <td>{item.category}</td>
                <td>{item.item}</td>
                <td><span className={`coverage-badge coverage-badge--${String(item.priority || 'medium').toLowerCase()}`}>{item.priority}</span></td>
                <td>{item.reason}</td>
                <td>{item.suggested_evidence}</td>
                <td>
                  <select value={status} onChange={(event) => onChange({ ...localState, [key]: event.target.value })}>
                    <option value="pending">pending</option>
                    <option value="done">done</option>
                    <option value="not_applicable">not applicable</option>
                  </select>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function DeveloperGuidance({ recommendations }: { recommendations: OWASPDeveloperRecommendation[] }) {
  if (!recommendations.length) return <div className="panel-message">No developer remediation guidance is available.</div>
  return (
    <div className="category-card-grid">
      {recommendations.map((item) => (
        <div className="result-card" key={`${item.category}-${item.issue_theme}`}>
          <div className="result-card__header"><strong>{item.category} {item.issue_theme}</strong><span className="badge">{item.references_label}</span></div>
          <p>{item.recommendation}</p>
          <p><strong>Implementation:</strong> {item.implementation_hint}</p>
          <p><strong>Validation:</strong> {item.validation_hint}</p>
        </div>
      ))}
    </div>
  )
}

function OWASPReportExportPanel({
  report,
  jsonPath,
  htmlPath,
  loading,
  message,
  disabled,
  onExport,
}: {
  report?: OWASPAssessmentReport
  jsonPath?: string
  htmlPath?: string
  loading: boolean
  message: string | null
  disabled: boolean
  onExport: () => void
}) {
  return (
    <div className="export-panel">
      <div className="report-summary-band">
        <div>
          <span>Safe testing statement</span>
          <p>{report?.safe_testing_statement || 'Authorised, non-destructive OWASP Assessment reporting only.'}</p>
        </div>
        <button className="primary-button" type="button" disabled={disabled || loading} onClick={onExport}>{loading ? 'Generating...' : 'Generate Markdown'}</button>
      </div>
      <div className="path-grid">
        <div><span>Markdown</span><code>{report?.markdown_report_path || 'Generated on request'}</code></div>
        <div><span>JSON</span><code>{jsonPath || 'Not available'}</code></div>
        <div><span>HTML</span><code>{htmlPath || 'Not available'}</code></div>
      </div>
      {message && <div className="panel-message">{message}</div>}
    </div>
  )
}

function AssessmentSummaryCards({ summary }: { summary?: OWASPAssessmentSummary }) {
  const cards = [
    ['OWASP version', summary?.owasp_version || '2025'],
    ['Evidence items', summary?.total_evidence_items ?? 0],
    ['Confirmed findings', summary?.confirmed_findings_count ?? 0],
    ['Strong indicators', summary?.strong_indicators_count ?? 0],
    ['Weak indicators', summary?.weak_indicators_count ?? 0],
    ['Manual validation', summary?.manual_validation_required_count ?? 0],
    ['Coverage gaps', summary?.coverage_gaps_count ?? 0],
    ['Assessment quality', `${summary?.assessment_quality_score ?? 0} - ${summary?.assessment_quality_label || 'Limited'}`],
  ]
  return <div className="summary-grid">{cards.map(([label, value]) => <div className="summary-card" key={label}><span>{label}</span><strong>{value}</strong></div>)}</div>
}

function AssessmentCoverageMatrix({ categories, categoryResults }: { categories: OWASPCategory[]; categoryResults: OWASPCategoryResult[] }) {
  const byId = new Map(categoryResults.map((item) => [item.owasp_id, item]))
  const rows = categories.length ? categories : categoryResults
  if (!rows.length) return <div className="panel-message">No OWASP Assessment Engine category results available.</div>
  return (
    <div className="table-shell">
      <table>
        <thead><tr><th>Category</th><th>Assessment Status</th><th>Coverage Status</th><th>Evidence</th><th>Confidence</th><th>Manual Validation</th><th>Top Recommendation</th></tr></thead>
        <tbody>
          {rows.map((category) => {
            const result = (byId.get(category.owasp_id) || {}) as OWASPCategoryResult
            return (
              <tr key={category.owasp_id}>
                <td>{category.owasp_id} {category.name}</td>
                <td>{String(result.assessment_status || 'not_assessed')}</td>
                <td>{String(result.coverage_status || 'not_assessed')}</td>
                <td>{Number(result.evidence_count || 0)}</td>
                <td><ConfidenceBadge confidence={String(result.highest_confidence || 'Low')} /></td>
                <td>{result.manual_validation_required ? 'Required' : Number(result.manual_validation_required_count || 0)}</td>
                <td>{String(result.recommendation_summary || result.recommendation_themes?.[0] || category.recommendation_theme || '')}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function CategoryResultCards({ categoryResults }: { categoryResults: OWASPCategoryResult[] }) {
  if (!categoryResults.length) return <div className="panel-message">No OWASP category results available.</div>
  return <div className="category-card-grid">{categoryResults.map((item) => (
    <div className="result-card" key={item.owasp_id}>
      <div className="result-card__header"><strong>{item.owasp_id} {item.name}</strong><ConfidenceBadge confidence={String(item.highest_confidence || 'Low')} /></div>
      <p>Status: {item.assessment_status || 'not_assessed'} | Coverage: {item.coverage_status || 'not_assessed'}</p>
      <p>Evidence: {item.evidence_count || 0} | Strong: {item.strong_indicator_count || 0} | Weak: {item.weak_indicator_count || 0} | Confirmed: {item.confirmed_count || 0}</p>
      <p>{item.limitations}</p>
    </div>
  ))}</div>
}

function EvidenceTable({ evidenceItems }: { evidenceItems: OWASPEvidenceItem[] }) {
  if (!evidenceItems.length) return <div className="panel-message">No OWASP evidence items available.</div>
  return (
    <div className="table-shell">
      <table>
        <thead><tr><th>Title</th><th>Source</th><th>Affected URL</th><th>Category</th><th>Strength</th><th>Confidence</th><th>Status</th><th>Manual</th></tr></thead>
        <tbody>{evidenceItems.map((item) => (
          <tr key={item.evidence_id || `${item.source}-${item.owasp_id}-${item.title}`}>
            <td>{item.title}</td><td>{item.source}</td><td>{item.affected_url}</td><td>{item.owasp_id} {item.owasp_name}</td><td>{item.evidence_strength}</td><td><ConfidenceBadge confidence={String(item.confidence || 'Low')} /></td><td>{item.assessment_status}</td><td>{item.manual_validation_required ? 'Required' : 'No'}</td>
          </tr>
        ))}</tbody>
      </table>
    </div>
  )
}

function ManualValidationPanel({ categoryResults, evidenceItems }: { categoryResults: OWASPCategoryResult[]; evidenceItems: OWASPEvidenceItem[] }) {
  const weakOrManual = evidenceItems.filter((item) => item.manual_validation_required || item.evidence_strength === 'weak_indicator')
  const categoryIds = new Set(['A01:2025', 'A06:2025', 'A09:2025', ...categoryResults.filter((item) => (item.manual_validation_required_count || 0) > 0).map((item) => item.owasp_id || '')])
  return (
    <div className="manual-validation-grid">
      <div>
        <h3>Categories</h3>
        {[...categoryIds].filter(Boolean).map((id) => <span className="badge" key={id}>{id}</span>)}
      </div>
      <div>
        <h3>Evidence Requiring Review</h3>
        {!weakOrManual.length ? <div className="panel-message">No weak or manual-validation evidence items available.</div> : (
          <ul>{weakOrManual.slice(0, 8).map((item) => <li key={item.evidence_id || item.title}>{item.owasp_id} - {item.title}</li>)}</ul>
        )}
      </div>
    </div>
  )
}

function ConfidenceBadge({ confidence }: { confidence: string }) {
  return <span className={`confidence-badge confidence-badge--${confidence.toLowerCase()}`}>{confidence}</span>
}

function buildLocalOWASPReport(
  summary: OWASPAssessmentSummary | undefined,
  categoryResults: OWASPCategoryResult[],
  evidenceItems: OWASPEvidenceItem[],
  coverageGaps: OWASPCoverageGap[],
  checklist: OWASPManualValidationItem[],
  recommendations: OWASPDeveloperRecommendation[],
): OWASPAssessmentReport | undefined {
  if (!summary && !categoryResults.length && !evidenceItems.length) return undefined
  const categoriesWithIndicators = categoryResults.filter((item) => Number(item.evidence_count || 0) > 0)
  const evidenceSummary = evidenceItems.reduce<Record<string, number>>((acc, item) => {
    const key = String(item.evidence_strength || 'informational')
    acc[key] = (acc[key] || 0) + 1
    return acc
  }, {})
  const bySource = evidenceItems.reduce<Record<string, Record<string, number>>>((acc, item) => {
    const source = String(item.source || 'unknown')
    const strength = String(item.evidence_strength || 'informational')
    acc[source] = acc[source] || {}
    acc[source][strength] = (acc[source][strength] || 0) + 1
    return acc
  }, {})
  return {
    report_id: String(summary?.generated_at || 'local-preview').replace(/[^A-Za-z0-9_.-]+/g, '_'),
    target: summary?.target || 'Selected result',
    generated_at: summary?.generated_at,
    owasp_version: summary?.owasp_version || '2025',
    overall_coverage_status: categoryResults.some((item) => item.coverage_status === 'assessed' || item.coverage_status === 'partially_assessed') ? 'partially_assessed' : 'coverage_gap',
    executive_summary: {
      target: summary?.target || 'Selected result',
      summary_text: `VulScan identified indicators across ${categoriesWithIndicators.length} OWASP categories. Several findings may require manual validation because automated evidence alone cannot confirm business logic or access-control impact.`,
      categories_with_indicators_count: categoriesWithIndicators.length,
      strong_indicators_count: evidenceSummary.strong_indicator || summary?.strong_indicators_count || 0,
      weak_indicators_count: evidenceSummary.weak_indicator || summary?.weak_indicators_count || 0,
      confirmed_findings_count: evidenceSummary.confirmed_finding || summary?.confirmed_findings_count || 0,
      manual_validation_required_count: summary?.manual_validation_required_count || evidenceItems.filter((item) => item.manual_validation_required).length,
      coverage_gaps_count: coverageGaps.length || summary?.coverage_gaps_count || 0,
      highest_signal_categories: categoriesWithIndicators.slice(0, 3).map((item) => ({ category: item.owasp_id, name: item.name, evidence_count: item.evidence_count })),
    },
    assessment_quality_score: {
      score: Number(summary?.assessment_quality_score || 0),
      label: summary?.assessment_quality_label || 'Limited Assessment',
      limitation: 'Assessment quality score reflects evidence coverage, not application security.',
    },
    category_results: categoryResults,
    evidence_strength_summary: {
      confirmed_findings_count: evidenceSummary.confirmed_finding || summary?.confirmed_findings_count || 0,
      strong_indicators_count: evidenceSummary.strong_indicator || summary?.strong_indicators_count || 0,
      weak_indicators_count: evidenceSummary.weak_indicator || summary?.weak_indicators_count || 0,
      informational_count: evidenceSummary.informational || 0,
      manual_validation_required_count: summary?.manual_validation_required_count || evidenceItems.filter((item) => item.manual_validation_required).length,
      by_source: bySource,
    },
    manual_validation_summary: { manual_validation_required_count: checklist.length, checklist },
    coverage_gaps: coverageGaps,
    developer_recommendations: recommendations,
    report_limitations: summary?.limitations || ['Manual validation is required for categories that cannot be confirmed from automated evidence.'],
    safe_testing_statement: 'This OWASP Assessment consolidates authorised, non-destructive VulScan evidence only.',
  }
}

function unique(values: string[]): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b))
}
