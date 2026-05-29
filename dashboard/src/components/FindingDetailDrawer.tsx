import type { Finding, RemediationRecord, RemediationUpdatePayload } from '../types/api'
import { formatValue, getCve, getCvss, getEpss, getExploitAvailable } from '../utils/format'
import { FindingBadge } from './FindingBadge'
import { RemediationStatusBadge } from './RemediationStatusBadge'
import { RemediationUpdateForm } from './RemediationUpdateForm'

interface FindingDetailDrawerProps {
  finding: Finding | null
  remediationRecord?: RemediationRecord | null
  remediationLoading?: boolean
  remediationError?: string | null
  remediationMessage?: string | null
  onUpdateRemediation?: (findingKey: string, payload: RemediationUpdatePayload) => Promise<void> | void
  onClose: () => void
}

function Field({ label, value }: { label: string; value: unknown }) {
  const text = formatValue(value)
  if (text === 'Not available') return null
  return (
    <div>
      <dt>{label}</dt>
      <dd>{typeof value === 'object' && value !== null ? JSON.stringify(redactDisplayObject(value), null, 2) : text}</dd>
    </div>
  )
}

function redactDisplayObject(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactDisplayObject)
  if (!value || typeof value !== 'object') return value
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, item]) => {
      const lowered = key.toLowerCase()
      if (
        lowered.includes('password') ||
        lowered.includes('token') ||
        lowered.includes('secret') ||
        lowered.includes('private_key') ||
        lowered.includes('cookie_value') ||
        lowered.includes('hidden_value') ||
        lowered.includes('payload') ||
        lowered.includes('shellcode') ||
        lowered.includes('exploit_code')
      ) {
        return [key, '[redacted]']
      }
      return [key, redactDisplayObject(item)]
    }),
  )
}

export function FindingDetailDrawer({
  finding,
  remediationRecord,
  remediationLoading = false,
  remediationError,
  remediationMessage,
  onUpdateRemediation = () => undefined,
  onClose,
}: FindingDetailDrawerProps) {
  if (!finding) return null
  const findingKey = String(finding.finding_key || finding.remediation_fingerprint || '')

  return (
    <aside className="detail-drawer" aria-label="Finding details">
      <div className="detail-drawer__header">
        <div>
          <h3>{formatValue(finding.title)}</h3>
          <div className="badge-row">
            <FindingBadge type="severity" value={finding.severity} />
            <FindingBadge type="priority" value={finding.priority_label} />
            <FindingBadge type="exploit" value={getExploitAvailable(finding)} />
            <RemediationStatusBadge status={remediationRecord?.status || finding.remediation_status} />
          </div>
        </div>
        <button className="ghost-button" type="button" onClick={onClose}>
          Close
        </button>
      </div>
      <dl className="detail-grid">
        <Field label="Source" value={finding.source} />
        <Field label="Category" value={finding.category} />
        <Field label="Description" value={finding.description} />
        <Field label="Evidence" value={finding.evidence} />
        <Field label="Evidence Details" value={finding.evidence_details} />
        <Field label="Impact" value={finding.impact} />
        <Field label="Recommendation" value={finding.recommendation} />
        <Field label="Verification" value={finding.verification} />
        <Field label="Limitation" value={finding.limitation} />
        <Field label="Risk Score" value={finding.risk_score} />
        <Field label="Risk Label" value={finding.risk_label} />
        <Field label="Priority Score" value={finding.priority_score} />
        <Field label="Priority Label" value={finding.priority_label} />
        <Field label="Priority Reasons" value={finding.priority_reasons} />
        <Field label="Recommended Action" value={finding.recommended_action} />
        <Field label="SLA Hint" value={finding.sla_hint} />
        <Field label="CVE" value={getCve(finding)} />
        <Field label="CVSS Score" value={getCvss(finding)} />
        <Field label="CVSS Vector" value={finding.cvss_vector ?? finding.evidence_details?.cvss_vector} />
        <Field label="EPSS Score" value={getEpss(finding)} />
        <Field label="EPSS Percentile" value={finding.epss_percentile ?? finding.evidence_details?.epss_percentile} />
        <Field label="Exploit Metadata" value={getExploitAvailable(finding)} />
        <Field label="Exploit Maturity" value={finding.exploit_maturity ?? finding.evidence_details?.exploit_maturity} />
        <Field label="Active Exploitation Reported" value={finding.active_exploitation_reported ?? finding.evidence_details?.active_exploitation_reported} />
        <Field label="Affected URLs" value={finding.affected_urls ?? finding.affected_url} />
        <Field label="Asset Criticality" value={finding.asset_criticality} />
        <Field label="Remediation Status" value={finding.remediation_status} />
        <Field label="Remediation Owner" value={remediationRecord?.owner ?? finding.remediation_owner} />
        <Field label="Remediation Due Date" value={remediationRecord?.due_date ?? finding.remediation_due_date} />
        <Field label="Latest Remediation Note" value={remediationRecord?.note ?? finding.remediation_note} />
      </dl>
      <div className="detail-remediation-panel">
        <h4>Remediation Tracking</h4>
        {remediationMessage ? <div className="success-message">{remediationMessage}</div> : null}
        {remediationError ? <div className="panel-message panel-message--error">{remediationError}</div> : null}
        <RemediationUpdateForm
          record={remediationRecord || {
            finding_key: findingKey,
            status: finding.remediation_status || 'open',
            owner: finding.remediation_owner,
            due_date: finding.remediation_due_date,
            note: finding.remediation_note,
          }}
          findingKey={findingKey}
          loading={remediationLoading}
          onSubmit={onUpdateRemediation}
        />
      </div>
    </aside>
  )
}
