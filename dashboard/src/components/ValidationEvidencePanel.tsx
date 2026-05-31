import type { SafeValidationResult } from '../types/api'

interface ValidationEvidencePanelProps {
  result?: SafeValidationResult | null
}

export function ValidationEvidencePanel({ result }: ValidationEvidencePanelProps) {
  if (!result) return <div className="panel-message">Select a validation result to review evidence summary and manual validation notes.</div>
  return (
    <div className="result-summary">
      <dl>
        <div><dt>Observed behaviour</dt><dd>{JSON.stringify(result.evidence_summary || {})}</dd></div>
        <div><dt>Request method</dt><dd>{result.request_method}</dd></div>
        <div><dt>Status code</dt><dd>{result.status_code ?? 'n/a'}</dd></div>
        <div><dt>OWASP indicators</dt><dd>{result.owasp_categories?.map((item) => `${item.owasp_id} ${item.owasp_name}`).join(', ') || 'None'}</dd></div>
        <div><dt>Limitation</dt><dd>{result.limitation}</dd></div>
      </dl>
    </div>
  )
}
