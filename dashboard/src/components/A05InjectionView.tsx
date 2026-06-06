import type { A05InjectionEvidenceItem, A05InjectionSummary } from '../types/api'
import { A05FormInputPanel } from './A05FormInputPanel'
import { A05ManualValidationChecklist } from './A05ManualValidationChecklist'
import { A05ParameterCandidateTable } from './A05ParameterCandidateTable'
import { A05RecommendationPanel } from './A05RecommendationPanel'
import { A05ReflectionEvidenceTable } from './A05ReflectionEvidenceTable'
import { A05SummaryCards } from './A05SummaryCards'

export function A05InjectionView({ summary, evidence = [] }: { summary?: A05InjectionSummary; evidence?: A05InjectionEvidenceItem[] }) {
  if (!summary?.enabled) {
    return (
      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>A05 Injection</h2>
          <p>A05 evidence is available when a scan or report is generated with A05 checks.</p>
        </div>
        <div className="panel-message">No A05 Injection candidate evidence is attached to the selected result.</div>
      </article>
    )
  }
  const apiRows = evidence.filter((item) => item.rule_group === 'api_input_indicators')
  return (
    <article className="panel panel--wide a05-panel">
      <div className="panel-heading">
        <div>
          <h2>A05 Injection</h2>
          <p>Injection candidates, input handling indicators, reflection indicators, parameter intelligence, and manual validation required status.</p>
        </div>
      </div>
      <A05SummaryCards summary={summary} />
      <h3>Parameter Candidates</h3>
      <A05ParameterCandidateTable items={evidence} />
      <h3>Reflection Evidence</h3>
      <A05ReflectionEvidenceTable items={evidence} />
      <h3>Form Input Candidates</h3>
      <A05FormInputPanel items={evidence} />
      <h3>API Input Candidates</h3>
      {!apiRows.length ? <div className="panel-message">No A05 API input candidates are attached to this result.</div> : (
        <div className="a05-list">
          {apiRows.map((item) => (
            <div className="a05-list-item" key={item.evidence_id}>
              <strong>{item.affected_url || 'API input candidate'}</strong>
              <span>{item.api_pattern || item.safe_evidence_summary}</span>
              <small>Parameters: {(item.parameter_names || []).join(', ') || item.affected_parameter || 'none observed'}; candidate score {item.candidate_score || 0}</small>
            </div>
          ))}
        </div>
      )}
      <h3>Manual Validation Checklist</h3>
      <A05ManualValidationChecklist />
      <h3>Recommendations</h3>
      <A05RecommendationPanel summary={summary} />
      {!!summary.limitations?.length && <p className="panel-message">Limitations: {summary.limitations.join('; ')}</p>}
    </article>
  )
}
