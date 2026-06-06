import { useEffect, useMemo, useState } from 'react'
import { buildOWASPAssessment, getOWASPCategories, getOWASPAssessmentRules, mapOWASP } from '../api/client'
import type {
  JobResultResponse,
  OWASPAssessmentResponse,
  OWASPAssessmentSummary,
  OWASPCategory,
  OWASPCategoryResult,
  OWASPCoverageGap,
  OWASPEvidenceItem,
  OWASPMapResponse,
  OWASPMappedItem,
  OWASPSummary,
  A01AccessControlEvidenceItem,
  A01AccessControlSummary,
  A03SupplyChainEvidenceItem,
  A03SupplyChainSummary,
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
  const existingCategoryResults = resultPayload?.owasp_category_results as OWASPCategoryResult[] | undefined
  const existingEvidenceItems = resultPayload?.owasp_evidence_items as OWASPEvidenceItem[] | undefined
  const existingCoverageGaps = resultPayload?.owasp_coverage_gaps as OWASPCoverageGap[] | undefined
  const a01Summary = resultPayload?.a01_access_control_summary as A01AccessControlSummary | undefined
  const a01Evidence = (resultPayload?.a01_access_control_evidence as A01AccessControlEvidenceItem[] | undefined) || []
  const a03Summary = resultPayload?.a03_supply_chain_summary as A03SupplyChainSummary | undefined
  const a03Evidence = (resultPayload?.a03_supply_chain_evidence as A03SupplyChainEvidenceItem[] | undefined) || []
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
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>OWASP Coverage Matrix</h2>
          <p>No indicator found does not mean the category is secure. It may mean the category was not assessed or requires authenticated/manual testing.</p>
        </div>
        <AssessmentCoverageMatrix categories={categories} categoryResults={categoryResults} />
      </article>

      <A01AccessControlView summary={a01Summary} evidence={a01Evidence} />

      <A03SupplyChainView summary={a03Summary} evidence={a03Evidence} />

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
        <EvidenceTable evidenceItems={evidenceItems} />
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>Manual Validation Required</h2>
          <p>A01, A06, A09, and weak indicators often need authorised manual review.</p>
        </div>
        <ManualValidationPanel categoryResults={categoryResults} evidenceItems={evidenceItems} />
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
                {coverageGaps.map((gap) => <tr key={gap.owasp_id}><td>{gap.owasp_id} {gap.owasp_name}</td><td>{gap.coverage_status}</td><td>{gap.explanation}</td></tr>)}
              </tbody>
            </table>
          </div>
        )}
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
                <td>{Number(result.manual_validation_required_count || 0)}</td>
                <td>{String(result.recommendation_themes?.[0] || category.recommendation_theme || '')}</td>
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
