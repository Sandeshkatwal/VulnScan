import { useState } from 'react'
import { checkProfessionalReportSafety, composeProfessionalReport } from '../api/client'
import type { ComposedReport, ProfessionalFinding, ReportComposerResponse } from '../types/api'
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
  status: 'draft',
  validation_status: 'manual_validation_required',
  retest_status: 'not_retested',
  owasp_categories: ['A02:2025'],
  technical_summary: 'VulScan identified a candidate requiring manual validation. The evidence does not confirm exploitability.',
  remediation: 'Harden security headers according to application context.',
  evidence_references: [],
}

export function ReportComposerView({ apiOnline, demoMode = false }: Props) {
  const [setup, setSetup] = useState({ title: 'VulScan OWASP Assessment Report', target: 'http://127.0.0.1:8000', assessment_type: 'owasp_assessment', report_status: 'draft' })
  const [selected, setSelected] = useState(true)
  const [safety, setSafety] = useState<ReportComposerResponse | null>(null)
  const [report, setReport] = useState<ComposedReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const includedFindings = selected ? [demoFinding] : []

  async function runSafetyCheck() {
    setLoading(true)
    setError(null)
    try {
      const response = demoMode || !apiOnline ? { export_allowed: true, status: 'allowed', blocked_findings: [] } : await checkProfessionalReportSafety({ findings: includedFindings, target: setup.target })
      setSafety(response)
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  async function compose(format: 'markdown' | 'html' | 'json') {
    setLoading(true)
    setError(null)
    try {
      const payload = { ...setup, findings: includedFindings, markdown: format === 'markdown', html: format === 'html', json: format === 'json' }
      const response = demoMode || !apiOnline ? { report: { ...setup, report_id: 'demo-composed-report', findings: includedFindings, export_paths: { [format]: `reports/composed/${format}/demo.${format === 'markdown' ? 'md' : format}` }, export_safety_status: 'allowed' } } : await composeProfessionalReport(payload)
      setReport(response.report || null)
      setSafety({ export_allowed: response.report?.export_safety_status !== 'blocked', status: response.report?.export_safety_status })
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
          Report Composer exports Markdown, HTML, and JSON only after Redacted Evidence and export safety checks pass. Candidate findings remain draft unless manually validated.
        </div>
        {error ? <ErrorAlert message={error} /> : null}
      </section>

      <section className="panel">
        <h3>Report Setup</h3>
        <label>Title<input value={setup.title} onChange={(event) => setSetup((current) => ({ ...current, title: event.target.value }))} /></label>
        <label>Target<input value={setup.target} onChange={(event) => setSetup((current) => ({ ...current, target: event.target.value }))} /></label>
        <label>Assessment Type<select value={setup.assessment_type} onChange={(event) => setSetup((current) => ({ ...current, assessment_type: event.target.value }))}><option value="owasp_assessment">OWASP Assessment</option><option value="authenticated_assessment">Authenticated Assessment</option><option value="web_application_assessment">Web Application Assessment</option><option value="retest_report">Retest Report</option></select></label>
        <label>Report Status<select value={setup.report_status} onChange={(event) => setSetup((current) => ({ ...current, report_status: event.target.value }))}><option>draft</option><option>ready_for_review</option><option>final</option></select></label>
      </section>

      <section className="panel">
        <h3>Section Manager</h3>
        {['Cover Page', 'Executive Summary', 'Scope and Methodology', 'Findings', 'OWASP Mapping', 'Evidence Summary', 'Retest Summary', 'Risk Acceptance', 'Appendices'].map((section) => <p key={section}>{section}</p>)}
      </section>

      <section className="panel">
        <h3>Findings Selection</h3>
        <label className="checkbox-row"><input type="checkbox" checked={selected} onChange={(event) => setSelected(event.target.checked)} /> Include {demoFinding.finding_id}: {demoFinding.title}</label>
        <p><strong>Validation:</strong> {demoFinding.validation_status}</p>
        <p><strong>Severity:</strong> {demoFinding.severity}</p>
      </section>

      <section className="panel">
        <h3>Executive Summary Builder</h3>
        <p>{report?.executive_summary?.summary ? String(report.executive_summary.summary) : 'A generated Executive Summary will appear after composition.'}</p>
      </section>

      <section className="panel">
        <h3>Export Safety Check</h3>
        <p><strong>Status:</strong> {safety?.status || 'not checked'}</p>
        <p><strong>Blocked Findings:</strong> {safety?.blocked_findings?.length || 0}</p>
        <button type="button" onClick={runSafetyCheck} disabled={loading}>Run Safety Check</button>
      </section>

      <section className="panel">
        <h3>Safe Export</h3>
        <div className="button-row">
          <button type="button" onClick={() => compose('markdown')} disabled={loading || !includedFindings.length}>Markdown</button>
          <button type="button" onClick={() => compose('html')} disabled={loading || !includedFindings.length}>HTML</button>
          <button type="button" onClick={() => compose('json')} disabled={loading || !includedFindings.length}>JSON</button>
        </div>
        <pre>{JSON.stringify(report?.export_paths || {}, null, 2)}</pre>
      </section>
    </div>
  )
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Request failed.'
}

