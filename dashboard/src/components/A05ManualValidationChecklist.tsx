const checklist = [
  'Review output encoding.',
  'Review server-side input validation.',
  'Review parameterised queries.',
  'Review template rendering context.',
  'Review API filter/sort handling.',
  'Review command/path/template-like parameters.',
  'Confirm impact manually before reporting.',
]

export function A05ManualValidationChecklist() {
  return (
    <div className="a05-checklist">
      {checklist.map((item) => <span key={item}>{item}</span>)}
      <small>Harmless marker only; no payloads were used; no exploitability confirmed.</small>
    </div>
  )
}
