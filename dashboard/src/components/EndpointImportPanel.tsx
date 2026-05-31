interface EndpointImportPanelProps {
  value: string
  disabled?: boolean
  onChange: (value: string) => void
}

export function EndpointImportPanel({ value, disabled = false, onChange }: EndpointImportPanelProps) {
  return (
    <label>
      <span>URLs and paths</span>
      <textarea
        rows={10}
        value={value}
        disabled={disabled}
        spellCheck={false}
        onChange={(event) => onChange(event.target.value)}
      />
      <small>One URL or path per line. Candidate results require manual validation.</small>
    </label>
  )
}
