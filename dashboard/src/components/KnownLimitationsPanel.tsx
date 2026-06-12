const limitations = [
  'Not a replacement for professional manual penetration testing.',
  'Many findings are indicators or candidates until manually validated.',
  'No automatic auth bypass testing, brute force, or destructive workflow execution.',
  'Demo mode uses simulated redacted data only.',
  'Public Beta may contain bugs.',
]

export function KnownLimitationsPanel() {
  return (
    <article className="panel">
      <div className="panel-heading">
        <h2>Known Limitations</h2>
        <p>Public Beta trust boundaries.</p>
      </div>
      <ul className="beta-list">
        {limitations.map((item) => <li key={item}>{item}</li>)}
      </ul>
    </article>
  )
}
