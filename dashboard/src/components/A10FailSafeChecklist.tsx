const checks = [
  'Review auth endpoints for fail-closed behaviour',
  'Review payment and billing error handling',
  'Review password reset error handling',
  'Review admin endpoints',
  'Ensure generic user-facing error messages',
  'Log diagnostic details safely server-side',
  'Avoid exposing stack traces or framework debug pages',
]

export function A10FailSafeChecklist() {
  return (
    <div className="a10-checklist">
      {checks.map((check) => <span key={check}>{check}</span>)}
      <small>No errors were forced and no payloads were sent. Manual validation required for fail-safe behaviour.</small>
    </div>
  )
}
