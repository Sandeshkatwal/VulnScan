interface Props {
  enabled: boolean
  onChange: (enabled: boolean) => void
}

export function ScreenshotModeToggle({ enabled, onChange }: Props) {
  return (
    <label className="toggle-row">
      <input type="checkbox" checked={enabled} onChange={(event) => onChange(event.target.checked)} />
      <span>Screenshot-Ready View</span>
    </label>
  )
}

