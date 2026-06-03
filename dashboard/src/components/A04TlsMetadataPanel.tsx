import type { A04TlsMetadata } from '../types/api'

export function A04TlsMetadataPanel({ metadata }: { metadata: A04TlsMetadata[] }) {
  if (!metadata.length) return <div className="panel-message">TLS metadata limitation: no TLS metadata was available for this assessment.</div>
  return (
    <div className="table-shell">
      <table>
        <thead><tr><th>Host</th><th>Issuer</th><th>Subject</th><th>Expiry</th><th>Days Until Expiry</th><th>Self-Signed Indicator</th><th>Hostname Match</th><th>TLS Metadata Limitation</th></tr></thead>
        <tbody>
          {metadata.map((item) => (
            <tr key={`${item.host}:${item.port || 443}`}>
              <td>{item.host}</td>
              <td>{item.issuer_common_name}</td>
              <td>{item.subject_common_name}</td>
              <td>{item.not_after}</td>
              <td>{item.days_until_expiry ?? 'Not available'}</td>
              <td>{String(item.self_signed_indicator ?? 'Not assessed')}</td>
              <td>{String(item.hostname_match ?? 'Not assessed')}</td>
              <td>{item.error || item.limitations?.join('; ')}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
