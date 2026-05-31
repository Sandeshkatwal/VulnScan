interface ValidationChecksSelectorProps {
  selected: string[]
  disabled?: boolean
  onChange: (checks: string[]) => void
}

const checks = [
  ['reflected_input_observation', 'Reflected input observation'],
  ['open_redirect_indicator', 'Open redirect indicator'],
  ['cors_indicator', 'CORS indicator'],
  ['directory_listing_indicator', 'Directory listing indicator'],
  ['default_file_exposure_indicator', 'Default file exposure indicator'],
  ['http_methods_indicator', 'HTTP methods indicator'],
]

export function ValidationChecksSelector({ selected, disabled = false, onChange }: ValidationChecksSelectorProps) {
  function toggle(value: string) {
    onChange(selected.includes(value) ? selected.filter((item) => item !== value) : [...selected, value])
  }
  return (
    <div className="checkbox-grid">
      {checks.map(([value, label]) => (
        <label className="demo-mode-toggle" key={value}>
          <input type="checkbox" checked={selected.includes(value)} disabled={disabled} onChange={() => toggle(value)} />
          <span>{label}</span>
        </label>
      ))}
    </div>
  )
}
