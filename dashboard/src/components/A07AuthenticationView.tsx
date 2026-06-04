import type { A07AuthenticationEvidenceItem, A07AuthenticationSummary } from '../types/api'
import { A07AuthEndpointTable } from './A07AuthEndpointTable'
import { A07AuthFormPanel } from './A07AuthFormPanel'
import { A07ManualValidationChecklist } from './A07ManualValidationChecklist'
import { A07RateLimitIndicatorPanel } from './A07RateLimitIndicatorPanel'
import { A07RecommendationPanel } from './A07RecommendationPanel'
import { A07SessionCookieTable } from './A07SessionCookieTable'
import { A07SummaryCards } from './A07SummaryCards'

export function A07AuthenticationView({ summary, evidence = [] }: { summary?: A07AuthenticationSummary; evidence?: A07AuthenticationEvidenceItem[] }) {
  if (!summary?.enabled) {
    return (
      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>A07 Authentication Failures</h2>
          <p>A07 evidence is available when a scan or report is generated with A07 checks.</p>
        </div>
        <div className="panel-message">No A07 Authentication Failures evidence is attached to the selected result.</div>
      </article>
    )
  }
  return (
    <article className="panel panel--wide a07-panel">
      <div className="panel-heading">
        <div>
          <h2>A07 Authentication Failures</h2>
          <p>Authentication indicators, session management indicators, login workflow evidence, and manual validation needs.</p>
        </div>
      </div>
      <A07SummaryCards summary={summary} />
      <h3>Authentication Endpoints</h3>
      <A07AuthEndpointTable items={evidence} />
      <h3>Session Cookies</h3>
      <A07SessionCookieTable items={evidence} />
      <h3>Auth Forms</h3>
      <A07AuthFormPanel items={evidence} />
      <h3>Rate-Limit Header Indicators</h3>
      <A07RateLimitIndicatorPanel items={evidence} />
      <h3>Manual Validation Checklist</h3>
      <A07ManualValidationChecklist />
      <h3>Recommendations</h3>
      <A07RecommendationPanel summary={summary} />
      {!!summary.limitations?.length && <p className="panel-message">Limitations: {summary.limitations.join('; ')}</p>}
    </article>
  )
}
