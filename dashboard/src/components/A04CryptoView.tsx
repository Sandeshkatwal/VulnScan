import type { A04CryptoEvidenceItem, A04CryptoSummary, A04TlsMetadata } from '../types/api'
import { A04CookieEvidenceTable } from './A04CookieEvidenceTable'
import { A04MixedContentPanel } from './A04MixedContentPanel'
import { A04RecommendationPanel } from './A04RecommendationPanel'
import { A04SummaryCards } from './A04SummaryCards'
import { A04TlsMetadataPanel } from './A04TlsMetadataPanel'
import { A04TransportEvidenceTable } from './A04TransportEvidenceTable'

interface A04CryptoViewProps {
  summary?: A04CryptoSummary
  evidence?: A04CryptoEvidenceItem[]
  tlsMetadata?: A04TlsMetadata[]
}

export function A04CryptoView({ summary, evidence = [], tlsMetadata = [] }: A04CryptoViewProps) {
  if (!summary?.enabled) {
    return (
      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>A04 Cryptographic Failures</h2>
          <p>A04 evidence is available when a scan or report is generated with A04 checks.</p>
        </div>
        <div className="panel-message">No A04 Cryptographic Failures evidence is attached to the selected result.</div>
      </article>
    )
  }

  return (
    <article className="panel panel--wide a04-panel">
      <div className="panel-heading">
        <div>
          <h2>A04 Cryptographic Failures</h2>
          <p>Transport security indicators, cookie security evidence, mixed content indicators, and TLS metadata.</p>
        </div>
      </div>
      <A04SummaryCards summary={summary} />

      <h3>Transport Evidence</h3>
      <A04TransportEvidenceTable items={evidence} />

      <h3>Cookie Evidence</h3>
      <A04CookieEvidenceTable items={evidence} />

      <h3>TLS Metadata</h3>
      <A04TlsMetadataPanel metadata={tlsMetadata} />

      <h3>Mixed Content</h3>
      <A04MixedContentPanel items={evidence} />

      <h3>Recommendations</h3>
      <A04RecommendationPanel summary={summary} />
      {!!summary.limitations?.length && <p className="panel-message">Limitations: {summary.limitations.join('; ')}</p>}
    </article>
  )
}
