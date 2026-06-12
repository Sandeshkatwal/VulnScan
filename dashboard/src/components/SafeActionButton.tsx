interface Props {
  children: string
  disabled?: boolean
  demoMode?: boolean
  liveAction?: boolean
  onClick: () => void
}

export function SafeActionButton({ children, disabled = false, demoMode = false, liveAction = false, onClick }: Props) {
  const blocked = disabled || (demoMode && liveAction)
  return (
    <button type="button" disabled={blocked} onClick={onClick} title={demoMode && liveAction ? 'Disabled in Portfolio Demo Mode because it would perform live work.' : 'Safe action'}>
      {children}
    </button>
  )
}

