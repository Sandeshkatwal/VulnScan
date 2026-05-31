interface ReconTargetImportProps {
  value: string
  disabled?: boolean
  onChange: (value: string) => void
}

export function ReconTargetImport({ value, disabled = false, onChange }: ReconTargetImportProps) {
  return (
    <label className="recon-target-import">
      <span>Targets</span>
      <textarea
        value={value}
        disabled={disabled}
        rows={8}
        spellCheck={false}
        placeholder={'127.0.0.1\nhttp://127.0.0.1:8000/\ndemo-web.local'}
        onChange={(event) => onChange(event.target.value)}
      />
      <small>One provided domain, host, URL, or IP per line. VulScan does not brute-force or query third-party sources.</small>
    </label>
  )
}
