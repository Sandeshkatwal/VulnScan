import { useMemo, useState } from 'react'
import { createEvidenceItem, exportEvidence, getEvidenceQuality, getEvidenceTimeline, linkEvidence, redactEvidenceText } from '../api/client'
import type { EvidenceVaultItem, JobResultResponse } from '../types/api'
import { ErrorAlert } from './ErrorAlert'

interface Props {
  apiOnline: boolean
  demoMode?: boolean
  jobResult?: JobResultResponse | null
}

const demoEvidence: EvidenceVaultItem = {
  evidence_id: 'demo-evidence-001',
  title: 'Manual A01 observation',
  evidence_type: 'manual_observation',
  source_module: 'access_control_test_planner',
  related_url: 'http://127.0.0.1:8000/admin/users',
  related_owasp_categories: ['A01:2025'],
  evidence_strength: 'manually_verified_secure',
  confidence: 'high',
  redaction_status: 'redacted',
  secret_detection_status: 'passed',
  evidence_quality_score: 90,
  evidence_quality_label: 'Excellent Evidence',
  safe_summary: 'Access denied for standard_user as expected.',
  redacted_request_summary: 'GET /admin/users with authorised test account label only.',
  redacted_response_summary: '403 access denied summary, response body not stored.',
  linked_finding_ids: ['finding-001'],
  linked_test_plan_ids: ['demo-plan-001'],
  timeline_events: [
    { event_id: 't1', event_type: 'created', timestamp: '2026-06-11T00:00:00+00:00', description: 'Evidence Item created.' },
    { event_id: 't2', event_type: 'redacted', timestamp: '2026-06-11T00:01:00+00:00', description: 'Redaction Quality Controls applied.' },
  ],
}

export function EvidenceVaultView({ apiOnline, demoMode = false, jobResult }: Props) {
  const result = jobResult?.result as Record<string, unknown> | null | undefined
  const resultItems = (result?.evidence_vault_items as EvidenceVaultItem[] | undefined) || []
  const [items, setItems] = useState<EvidenceVaultItem[]>(resultItems.length ? resultItems : [demoEvidence])
  const [selectedId, setSelectedId] = useState(items[0]?.evidence_id || '')
  const [redactionText, setRedactionText] = useState('Authorization: Bearer example-redacted-by-check')
  const [redactedOutput, setRedactedOutput] = useState('')
  const [quality, setQuality] = useState<Record<string, unknown> | null>(null)
  const [timeline, setTimeline] = useState<Record<string, unknown>[]>(demoEvidence.timeline_events || [])
  const [exportStatus, setExportStatus] = useState<Record<string, unknown> | null>(null)
  const [linkTarget, setLinkTarget] = useState('finding-001')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const selected = useMemo(() => items.find((item) => item.evidence_id === selectedId) || items[0], [items, selectedId])
  const summary = buildSummary(items)

  async function addEvidence() {
    setLoading(true)
    setError(null)
    try {
      const payload = { title: 'Manual A01 observation', evidence_type: 'manual_observation', safe_summary: 'Access denied for standard_user as expected', related_owasp_categories: ['A01:2025'], evidence_strength: 'manually_verified_secure' }
      const response = demoMode || !apiOnline ? { evidence_vault_item: { ...demoEvidence, evidence_id: `demo-evidence-${Date.now()}` } } : await createEvidenceItem(payload)
      if (response.evidence_vault_item) {
        setItems((current) => [response.evidence_vault_item as EvidenceVaultItem, ...current])
        setSelectedId(response.evidence_vault_item.evidence_id || '')
      }
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  async function runRedactionCheck() {
    setLoading(true)
    setError(null)
    try {
      const response = demoMode || !apiOnline ? { redacted_text: redactionText.replace(/Authorization: Bearer .+/i, 'Authorization: Bearer [REDACTED-BEARER]') } : await redactEvidenceText(redactionText)
      setRedactedOutput(String(response.redacted_text || ''))
      setRedactionText('')
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  async function refreshQuality() {
    if (!selected?.evidence_id) return
    setLoading(true)
    setError(null)
    try {
      const response = demoMode || !apiOnline ? { evidence_quality: { score: selected.evidence_quality_score || 90, label: selected.evidence_quality_label || 'Excellent Evidence', suggestions: [] } } : await getEvidenceQuality(selected.evidence_id)
      setQuality(response.evidence_quality || null)
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  async function refreshTimeline() {
    if (!selected?.evidence_id) return
    setLoading(true)
    setError(null)
    try {
      const response = demoMode || !apiOnline ? { timeline_events: selected.timeline_events || [] } : await getEvidenceTimeline(selected.evidence_id)
      setTimeline((response.timeline_events as Record<string, unknown>[] | undefined) || [])
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  async function linkSelectedEvidence() {
    if (!selected?.evidence_id) return
    setLoading(true)
    setError(null)
    try {
      const response = demoMode || !apiOnline ? { evidence_vault_item: { ...selected, linked_finding_ids: [...(selected.linked_finding_ids || []), linkTarget] } } : await linkEvidence(selected.evidence_id, { link_type: 'finding', linked_id: linkTarget })
      if (response.evidence_vault_item) setItems((current) => current.map((item) => item.evidence_id === selected.evidence_id ? response.evidence_vault_item as EvidenceVaultItem : item))
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  async function exportSelectedEvidence() {
    if (!selected?.evidence_id) return
    setLoading(true)
    setError(null)
    try {
      const response = demoMode || !apiOnline ? { export_allowed: selected.secret_detection_status !== 'failed', export_paths: { json: 'reports/evidence_vault/exports/demo.json', markdown: 'reports/evidence_vault/exports/demo.md' } } : await exportEvidence({ evidence_ids: [selected.evidence_id], json: true, markdown: true })
      setExportStatus(response)
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="content-grid evidence-vault">
      <article className="panel panel--wide">
        <div className="panel-heading">
          <div><h2>Evidence Vault</h2><p>Redacted Evidence, Redaction Quality Controls, Evidence Quality Score, Evidence Timeline, and Report Evidence Linking.</p></div>
          <button className="primary-button" type="button" disabled={loading} onClick={() => void addEvidence()}>Add Evidence Item</button>
        </div>
        <div className="auth-safety-notice">Evidence Vault stores redacted evidence summaries only. It blocks export if secrets or raw authentication material are detected.</div>
        <ErrorAlert message={error} />
      </article>

      <article className="panel panel--wide"><div className="planner-summary">
        <Metric label="Total Evidence" value={summary.total} /><Metric label="Passed Redaction" value={summary.redacted} /><Metric label="Pending" value={summary.pending} /><Metric label="Failed Checks" value={summary.failed} /><Metric label="Blocked Export" value={summary.blocked} /><Metric label="Average Quality" value={summary.average} />
      </div></article>

      <article className="panel panel--wide">
        <div className="panel-heading"><h2>Evidence Table</h2><p>Redaction status, quality, and linked report context.</p></div>
        <div className="table-shell"><table><thead><tr><th>Evidence ID</th><th>Title</th><th>Type</th><th>Source</th><th>OWASP</th><th>Strength</th><th>Confidence</th><th>Redaction</th><th>Quality</th></tr></thead><tbody>
          {items.map((item) => <tr key={item.evidence_id} onClick={() => setSelectedId(item.evidence_id || '')}><td>{item.evidence_id}</td><td>{item.title}</td><td>{item.evidence_type}</td><td>{item.source_module}</td><td>{(item.related_owasp_categories || []).join(', ')}</td><td>{item.evidence_strength}</td><td>{item.confidence}</td><td><StatusBadge status={item.redaction_status} /></td><td><QualityBadge score={item.evidence_quality_score || 0} label={item.evidence_quality_label} /></td></tr>)}
        </tbody></table></div>
      </article>

      {selected && <article className="panel panel--wide">
        <div className="panel-heading"><h2>Evidence Detail</h2><p>Safe summaries and Report Evidence Linking only.</p></div>
        <div className="manual-plan-card">
          <div><span>Safe Summary</span><p>{selected.safe_summary}</p></div>
          <div><span>Redacted Request Summary</span><p>{selected.redacted_request_summary || 'Not recorded'}</p></div>
          <div><span>Redacted Response Summary</span><p>{selected.redacted_response_summary || 'Not recorded'}</p></div>
          <div><span>Linked Findings</span><p>{(selected.linked_finding_ids || []).join(', ') || 'None'}</p></div>
          <div><span>Linked Test Plans</span><p>{(selected.linked_test_plan_ids || []).join(', ') || 'None'}</p></div>
          <div><span>Linked Replay Plans</span><p>{(selected.linked_replay_plan_ids || []).join(', ') || 'None'}</p></div>
          <div><span>Linked Business Logic Plans</span><p>{(selected.linked_business_logic_plan_ids || []).join(', ') || 'None'}</p></div>
          <div><span>Limitations</span><p>{(selected.limitations || []).join('; ')}</p></div>
        </div>
      </article>}

      <article className="panel">
        <div className="panel-heading"><h2>Redaction Check</h2><p>Temporary Secret Detection helper. Redacted output only is shown.</p></div>
        <div className="planner-form">
          <label><span>Temporary Text</span><textarea value={redactionText} onChange={(event) => setRedactionText(event.target.value)} rows={4} /></label>
          <button className="secondary-button" type="button" disabled={loading || !redactionText} onClick={() => void runRedactionCheck()}>Run Redaction Check</button>
          {redactedOutput && <pre className="report-template-preview">{redactedOutput}</pre>}
        </div>
      </article>

      <article className="panel">
        <div className="panel-heading"><h2>Evidence Quality</h2><p>Quality score is evidence quality, not severity.</p></div>
        <button className="secondary-button" type="button" disabled={loading || !selected} onClick={() => void refreshQuality()}>Calculate Quality</button>
        <pre className="report-template-preview">{JSON.stringify(quality || { score: selected?.evidence_quality_score || 0, label: selected?.evidence_quality_label || 'Not calculated' }, null, 2)}</pre>
      </article>

      <article className="panel">
        <div className="panel-heading"><h2>Evidence Timeline</h2><p>Chain-of-Custody Style Timeline.</p></div>
        <button className="secondary-button" type="button" disabled={loading || !selected} onClick={() => void refreshTimeline()}>Refresh Timeline</button>
        <ul className="checklist-list">{timeline.map((event) => <li key={String(event.event_id)}><strong>{String(event.event_type || '')}</strong><span>{String(event.timestamp || '')}</span><p>{String(event.description || '')}</p></li>)}</ul>
      </article>

      <article className="panel">
        <div className="panel-heading"><h2>Evidence Linking</h2><p>Link Evidence Items to findings, tests, plans, reports, or submissions.</p></div>
        <div className="planner-form">
          <label><span>Finding ID</span><input value={linkTarget} onChange={(event) => setLinkTarget(event.target.value)} /></label>
          <button className="secondary-button" type="button" disabled={loading || !selected} onClick={() => void linkSelectedEvidence()}>Link Evidence</button>
        </div>
      </article>

      <article className="panel">
        <div className="panel-heading"><h2>Export Safety</h2><p>Export Safety Check blocks unsafe evidence.</p></div>
        <button className="secondary-button" type="button" disabled={loading || !selected} onClick={() => void exportSelectedEvidence()}>Export JSON/Markdown</button>
        <pre className="report-template-preview">{JSON.stringify(exportStatus || { status: 'not_requested' }, null, 2)}</pre>
      </article>
    </section>
  )
}

function Metric({ label, value }: { label: string; value: number }) {
  return <div><span>{label}</span><strong>{value}</strong></div>
}

function StatusBadge({ status }: { status?: string }) {
  const tone = status === 'redacted' || status === 'not_required' ? 'ok' : status === 'failed_secret_check' || status === 'blocked_from_export' ? 'critical' : 'warn'
  return <span className={`status-badge status-badge--${tone}`}>{status || 'unknown'}</span>
}

function QualityBadge({ score, label }: { score: number; label?: string }) {
  const tone = score >= 85 ? 'ok' : score >= 50 ? 'warn' : 'critical'
  return <span className={`status-badge status-badge--${tone}`}>{score} {label || ''}</span>
}

function buildSummary(items: EvidenceVaultItem[]) {
  const scores = items.map((item) => item.evidence_quality_score || 0)
  return {
    total: items.length,
    redacted: items.filter((item) => item.redaction_status === 'redacted' || item.redaction_status === 'not_required').length,
    pending: items.filter((item) => item.redaction_status === 'pending_redaction').length,
    failed: items.filter((item) => item.secret_detection_status === 'failed' || item.redaction_status === 'failed_secret_check').length,
    blocked: items.filter((item) => item.redaction_status === 'blocked_from_export' || item.secret_detection_status === 'failed').length,
    average: scores.length ? Math.round(scores.reduce((sum, score) => sum + score, 0) / scores.length) : 0,
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Request failed.'
}
