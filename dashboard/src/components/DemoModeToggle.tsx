interface DemoModeToggleProps {
  enabled: boolean
  envEnabled: boolean
  onChange: (enabled: boolean) => void
}

export function DemoModeToggle({ enabled, envEnabled, onChange }: DemoModeToggleProps) {
  return (
    <label className="demo-mode-toggle">
      <input type="checkbox" checked={enabled} onChange={(event) => onChange(event.target.checked)} />
      <span>Demo Mode</span>
      <small>{envEnabled ? 'Enabled by environment' : 'Local UI toggle'}</small>
    </label>
  )
}
