$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $repoRoot ".venv311\Scripts\python.exe"
$dashboard = Join-Path $repoRoot "dashboard"

if (-not (Test-Path $python)) {
    Write-Error "Python virtual environment not found at .venv311. Run the installation steps first."
}

Write-Host "Running backend tests..."
& $python -m pytest

Write-Host "Building dashboard..."
Push-Location $dashboard
try {
    npm run build
}
finally {
    Pop-Location
}

Write-Host "Release test checks completed."
