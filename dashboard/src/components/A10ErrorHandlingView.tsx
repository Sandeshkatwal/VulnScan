import type { A10ErrorHandlingEvidenceItem, A10ErrorHandlingSummary } from '../types/api'
import { A10ErrorEvidenceTable } from './A10ErrorEvidenceTable'
import { A10FailSafeChecklist } from './A10FailSafeChecklist'
import { A10FrameworkIndicatorPanel } from './A10FrameworkIndicatorPanel'
import { A10RecommendationPanel } from './A10RecommendationPanel'
import { A10StatusCodePanel } from './A10StatusCodePanel'
import { A10SummaryCards } from './A10SummaryCards'

export function A10ErrorHandlingView({ summary, evidence = [] }: { summary?: A10ErrorHandlingSummary; evidence?: A10ErrorHandlingEvidenceItem[] }) {
  if (!summary?.enabled) {
    return (
      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>A10 Error Handling</h2>
          <p>A10 evidence is available when a scan or report is generated with A10 checks.</p>
        </div>
        <div className="panel-message">No A10 Mishandling of Exceptional Conditions evidence is attached to the selected result.</div>
      </article>
    )
  }
  return (
    <article className="panel panel--wide a10-panel">
      <div className="panel-heading">
        <div>
          <h2>A10 Error Handling</h2>
          <p>Error-handling indicators, exception exposure evidence, verbose error evidence, framework debug indicators, and manual validation required notes.</p>
        </div>
      </div>
      <A10SummaryCards summary={summary} />
      <h3>Error Evidence</h3>
      <A10ErrorEvidenceTable items={evidence} />
      <h3>Status Code Pattern Analysis</h3>
      <A10StatusCodePanel items={evidence} />
      <h3>Framework Debug Indicators</h3>
      <A10FrameworkIndicatorPanel items={evidence} />
      <h3>Fail-Safe Checklist</h3>
      <A10FailSafeChecklist />
      <h3>Recommendations</h3>
      <A10RecommendationPanel summary={summary} />
      {!!summary.limitations?.length && <p className="panel-message">Limitations: {summary.limitations.join('; ')}</p>}
    </article>
  )
}
