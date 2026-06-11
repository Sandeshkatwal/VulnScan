import { useEffect, useMemo, useState } from 'react'
import { createProfessionalFinding, getProfessionalFindings } from '../api/client'
import type { ProfessionalFinding } from '../types/api'
import { ErrorAlert } from './ErrorAlert'

interface Props {
  apiOnline: boolean
  demoMode?: boolean
}

const demoFinding: ProfessionalFinding = {
  finding_id: 'finding-001',
  title: 'Missing CSP Header',
  severity: 'Low',
  confidence: 'Low',
  owasp_categories: ['A02:2025'],
  status: 'draft',
  validation_status: 'manual_validation_required',
  retest_status: 'not_retested',
  risk_score: 20,
  technical_summary: 'VulScan identified a candidate requiring manual validation. The evidence does not confirm exploitability.',
  business_impact: 'Browser-side defence in depth may be reduced.',
  technical_impact: 'The absence of CSP can reduce protection against certain content injection scenarios.',
  remediation: 'Harden security headers according to application context.',
  evidence_references: ['demo-evidence-001'],
  evidence_quality_summary: { score: 80, label: 'strong' },
  export_safety_status: { status: 'allowed' },
}

export function FindingBuilderView({ apiOnline, demoMode = false }: Props) {
  const [findings, setFindings] = useState<ProfessionalFinding[]>([demoFinding])
  const [selectedId, setSelectedId] = useState('finding-001')
  const [draft, setDraft] = useState({ title: 'Missing CSP Header', severity: 'Low', owasp: 'A02:2025', summary: 'Content-Security-Policy header was not observed.' })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const selected = useMemo(() => findings.find((finding) => finding.finding_id === selectedId) || findings[0], [findings, selectedId])

  useEffect(() => {
    async function load() {
      if (demoMode || !apiOnline) return
      setLoading(true)
      setError(null)
      try {
        const response = await getProfessionalFindings()
        if (response.findings?.length) {
          setFindings(response.findings)
          setSelectedId(response.findings[0].finding_id || '')
        }
      } catch (caught) {
        setError(errorMessage(caught))
      } finally {
        setLoading(false)
      }
    }
    void load()
  }, [apiOnline, demoMode])

  async function createDraft() {
    setLoading(true)
    setError(null)
    try {
      const payload = {
        title: draft.title,
        severity: draft.severity,
        confidence: 'Low',
        validation_status: 'manual_validation_required',
        owasp_categories: draft.owasp ? [draft.owasp] : [],
        technical_summary: draft.summary,
        status: 'draft',
      }
      const response = demoMode || !apiOnline ? { finding: { ...demoFinding, ...payload, finding_id: `finding-${Date.now()}` } } : await createProfessionalFinding(payload)
      if (response.finding) {
        setFindings((current) => [response.finding as ProfessionalFinding, ...current])
        setSelectedId(response.finding.finding_id || '')
      }
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="dashboard-grid">
      <section className="panel panel-wide">
        <div className="notice-box">
          Findings use redacted evidence only. Candidate findings are not labelled confirmed unless manual validation supports that status.
        </div>
        {error ? <ErrorAlert message={error} /> : null}
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Finding ID</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>OWASP</th>
                <th>Status</th>
                <th>Validation</th>
                <th>Retest</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((finding) => (
                <tr key={finding.finding_id} className={finding.finding_id === selectedId ? 'selected-row' : ''} onClick={() => setSelectedId(finding.finding_id || '')}>
                  <td>{finding.finding_id}</td>
                  <td>{finding.title}</td>
                  <td>{finding.severity}</td>
                  <td>{finding.confidence}</td>
                  <td>{(finding.owasp_categories || []).join(', ')}</td>
                  <td>{finding.status}</td>
                  <td>{finding.validation_status}</td>
                  <td>{finding.retest_status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <h3>Create Finding Draft</h3>
        <label>Title<input value={draft.title} onChange={(event) => setDraft((current) => ({ ...current, title: event.target.value }))} /></label>
        <label>Severity<select value={draft.severity} onChange={(event) => setDraft((current) => ({ ...current, severity: event.target.value }))}><option>Informational</option><option>Low</option><option>Medium</option><option>High</option><option>Critical</option></select></label>
        <label>OWASP Category<input value={draft.owasp} onChange={(event) => setDraft((current) => ({ ...current, owasp: event.target.value }))} /></label>
        <label>Technical Summary<textarea value={draft.summary} onChange={(event) => setDraft((current) => ({ ...current, summary: event.target.value }))} /></label>
        <button type="button" onClick={createDraft} disabled={loading}>{loading ? 'Working...' : 'Save Draft'}</button>
      </section>

      <section className="panel">
        <h3>Finding Editor</h3>
        <p><strong>{selected?.title}</strong></p>
        <p>{selected?.technical_summary}</p>
        <p><strong>Business Impact:</strong> {selected?.business_impact || 'Not set'}</p>
        <p><strong>Technical Impact:</strong> {selected?.technical_impact || 'Not set'}</p>
        <p><strong>Developer Remediation:</strong> {selected?.remediation || selected?.developer_guidance || 'Not set'}</p>
        <p><strong>Validation Guidance:</strong> {selected?.validation_guidance || 'Manual validation required before confirmed wording.'}</p>
      </section>

      <section className="panel">
        <h3>Evidence Link Panel</h3>
        <p><strong>Evidence References:</strong> {(selected?.evidence_references || []).join(', ') || 'None'}</p>
        <p><strong>Evidence Quality:</strong> {String(selected?.evidence_quality_summary?.score || 'Not scored')}</p>
        <p><strong>Export Safety:</strong> {String((selected?.export_safety_status as Record<string, unknown> | undefined)?.status || 'not checked')}</p>
      </section>

      <section className="panel">
        <h3>Risk Rating</h3>
        <p><strong>Risk Score:</strong> {selected?.risk_score ?? 0}</p>
        <p>{String(selected?.risk_rating?.risk_rationale || 'Risk is constrained by confidence, evidence strength, and retest status.')}</p>
      </section>

      <section className="panel">
        <h3>Retest Status</h3>
        <p><strong>Status:</strong> {selected?.retest_status}</p>
        <p>{selected?.retest_notes || 'No retest notes recorded.'}</p>
      </section>
    </div>
  )
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Request failed.'
}

