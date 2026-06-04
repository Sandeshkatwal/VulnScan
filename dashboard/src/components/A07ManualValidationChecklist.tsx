const checklist = [
  'Review login controls.',
  'Review password reset flow.',
  'Review session cookie attributes.',
  'Review remember-me behaviour.',
  'Review MFA/2FA if present.',
  'Review account lockout and rate limiting manually.',
  'Review token exposure in URLs.',
  'Review logout and session invalidation manually.',
]

export function A07ManualValidationChecklist() {
  return <div className="a07-checklist">{checklist.map((item) => <span key={item}>{item}</span>)}<small>No brute force was performed. No credentials were used.</small></div>
}
