import type { A05InjectionEvidenceItem } from '../types/api'

export function A05FormInputPanel({ items = [] }: { items?: A05InjectionEvidenceItem[] }) {
  const rows = items.filter((item) => item.rule_group === 'form_input_indicators')
  if (!rows.length) return <div className="panel-message">No A05 form input candidates are attached to this result.</div>
  return (
    <div className="a05-list">
      {rows.slice(0, 8).map((item) => (
        <div className="a05-list-item" key={item.evidence_id}>
          <strong>{item.form_action || item.affected_url || 'Form input candidate'}</strong>
          <span>Input names: {(item.input_names || [item.affected_parameter]).filter(Boolean).join(', ') || 'names unavailable'}</span>
          <span>Input types: {(item.input_types || [item.input_type]).filter(Boolean).join(', ') || 'types unavailable'}</span>
          <small>{item.candidate_reason || 'manual validation required'}; field values were not stored.</small>
        </div>
      ))}
    </div>
  )
}
