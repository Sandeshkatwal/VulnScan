$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $repoRoot ".venv311\Scripts\python.exe"

if (-not (Test-Path $python)) {
    Write-Error "Python virtual environment not found at .venv311. Run the installation steps first."
}

Set-Location $repoRoot
& $python -m scanner.main api --host 127.0.0.1 --port 8088
