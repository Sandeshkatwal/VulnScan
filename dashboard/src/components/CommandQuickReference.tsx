const commands = [
  '.\\.venv311\\Scripts\\python.exe -m scanner.main version',
  '.\\.venv311\\Scripts\\python.exe -m scanner.main health',
  '.\\.venv311\\Scripts\\python.exe -m scanner.main diagnostics --json',
  '.\\.venv311\\Scripts\\python.exe scripts\\public_beta_check.py',
  'npm run build',
]

export function CommandQuickReference() {
  return (
    <article className="panel">
      <div className="panel-heading">
        <h2>Command Quick Reference</h2>
        <p>Public Beta verification commands.</p>
      </div>
      <div className="command-list">
        {commands.map((command) => <code key={command}>{command}</code>)}
      </div>
    </article>
  )
}
