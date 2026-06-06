import type { A08IntegrityEvidenceItem, A08IntegritySummary } from '../types/api'

function score(item: A08IntegrityEvidenceItem) {
  return typeof item.candidate_score === 'number' ? item.candidate_score : 0
}

function ConfidenceBadge({ confidence }: { confidence?: string }) {
  return <span className={`confidence-badge confidence-badge--${(confidence || 'low').toLowerCase()}`}>{confidence || 'Low'}</span>
}

function SummaryCards({ summary }: { summary: A08IntegritySummary }) {
  const cards = [
    ['total A08 candidates', summary.total_evidence_items || 0],
    ['high-interest candidates', summary.high_interest_count || 0],
    ['upload workflow candidates', summary.upload_candidate_count || 0],
    ['import/export candidates', summary.import_export_candidate_count || 0],
    ['webhook/callback candidates', summary.webhook_callback_candidate_count || 0],
    ['update/plugin candidates', summary.update_workflow_candidate_count || 0],
    ['SRI indicators', summary.sri_indicator_count || 0],
    ['manual validation required', summary.manual_validation_required_count || 0],
  ]
  return (
    <div className="metric-grid a08-summary-grid">
      {cards.map(([label, value]) => (
        <div className="metric-card" key={String(label)}>
          <span>{label}</span>
          <strong>{value}</strong>
        </div>
      ))}
    </div>
  )
}

function WorkflowTable({ items }: { items: A08IntegrityEvidenceItem[] }) {
  const rows = items
    .filter((item) => item.rule_group !== 'subresource_integrity_indicators')
    .sort((a, b) => score(b) - score(a))
    .slice(0, 40)
  if (!rows.length) return <div className="panel-message">No workflow candidates are attached to this result.</div>
  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead>
          <tr>
            <th>Endpoint/path</th>
            <th>Workflow type</th>
            <th>Candidate reason</th>
            <th>Score</th>
            <th>Confidence</th>
            <th>Manual validation note</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((item) => (
            <tr key={item.evidence_id || `${item.rule_id}-${item.affected_url}`}>
              <td>{item.affected_url || 'metadata only'}</td>
              <td>{item.workflow_type || 'integrity indicator'}</td>
              <td>{item.title || item.rule_id}</td>
              <td>{score(item)}</td>
              <td><ConfidenceBadge confidence={item.confidence} /></td>
              <td>{item.manual_validation_required ? 'manual validation required' : 'review evidence'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function SRIAnalysisPanel({ items }: { items: A08IntegrityEvidenceItem[] }) {
  const rows = items.filter((item) => item.rule_group === 'subresource_integrity_indicators')
  if (!rows.length) return <div className="panel-message">No Subresource Integrity evidence is attached to this result.</div>
  return (
    <div className="a08-list">
      {rows.map((item) => (
        <div className="a08-list-item" key={item.evidence_id || item.affected_url}>
          <strong>{item.title || 'Subresource Integrity evidence'}</strong>
          <span>{item.affected_url || item.third_party_domain || 'resource metadata'}</span>
          <small>{item.safe_evidence_summary || 'manual validation required'}</small>
        </div>
      ))}
    </div>
  )
}

function UploadImportPanel({ items }: { items: A08IntegrityEvidenceItem[] }) {
  const rows = items.filter((item) => ['upload_workflow_indicators', 'import_export_integrity_indicators'].includes(item.rule_group || ''))
  return (
    <div className="a08-panel-grid">
      <div>
        <h4>Observed workflows</h4>
        {!rows.length ? <p>No upload/import workflow indicators are attached.</p> : rows.slice(0, 10).map((item) => <p key={item.evidence_id}>{item.affected_url || item.title}</p>)}
      </div>
      <div>
        <h4>Validation plan</h4>
        <p>Review file upload validation, import data schema validation, authorization, tamper protection, and audit logging.</p>
        <p>Use only approved test data and safe programme assets.</p>
      </div>
    </div>
  )
}

function WebhookCallbackPanel({ items }: { items: A08IntegrityEvidenceItem[] }) {
  const rows = items.filter((item) => ['webhook_callback_indicators', 'trusted_data_boundary_indicators'].includes(item.rule_group || ''))
  return (
    <div className="a08-panel-grid">
      <div>
        <h4>Observed indicators</h4>
        {!rows.length ? <p>No webhook/callback indicators are attached.</p> : rows.slice(0, 10).map((item) => <p key={item.evidence_id}>{item.affected_parameter || item.affected_url || item.title}</p>)}
      </div>
      <div>
        <h4>Review notes</h4>
        <p>Review signature verification, replay protection, timestamp validation, allowed callback domains, and state parameter validation.</p>
        <p>No webhooks were triggered.</p>
      </div>
    </div>
  )
}

function ManualChecklist() {
  const items = [
    'review file upload validation',
    'review import data schema validation',
    'review webhook signature and replay protection',
    'review update/plugin package signing',
    'review external script integrity',
    'review deserialisation safety',
    'avoid state-changing tests unless approved',
  ]
  return (
    <ul className="checklist-list">
      {items.map((item) => <li key={item}>{item}</li>)}
    </ul>
  )
}

export function A08IntegrityView({ summary, evidence = [] }: { summary?: A08IntegritySummary; evidence?: A08IntegrityEvidenceItem[] }) {
  if (!summary?.enabled) {
    return (
      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>A08 Software/Data Integrity</h2>
          <p>A08 integrity indicator evidence is available when a scan or report is generated with A08 checks.</p>
        </div>
        <div className="panel-message">No A08 Software or Data Integrity Failures evidence is attached to the selected result.</div>
      </article>
    )
  }
  return (
    <article className="panel panel--wide a08-panel">
      <div className="panel-heading">
        <div>
          <h2>A08 Software/Data Integrity</h2>
          <p>Integrity indicators for upload/import workflows, webhooks, update surfaces, Subresource Integrity evidence, and trusted-data boundaries.</p>
        </div>
      </div>
      <SummaryCards summary={summary} />
      <p className="panel-message">Candidate and indicator review only. Manual validation required; no uploads were performed, no webhooks were triggered, and no update endpoints were called.</p>
      <h3>Workflow Candidates</h3>
      <WorkflowTable items={evidence} />
      <h3>Subresource Integrity Analysis</h3>
      <SRIAnalysisPanel items={evidence} />
      <h3>Upload/Import Review</h3>
      <UploadImportPanel items={evidence} />
      <h3>Webhook/Callback Review</h3>
      <WebhookCallbackPanel items={evidence} />
      <h3>Manual Validation Checklist</h3>
      <ManualChecklist />
      <h3>Recommendations</h3>
      <div className="a08-list">
        {(summary.recommendations || []).map((item) => <div className="a08-list-item" key={item}>{item}</div>)}
      </div>
    </article>
  )
}
