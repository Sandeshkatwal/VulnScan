$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$dashboard = Join-Path $repoRoot "dashboard"
$python = Join-Path $repoRoot ".venv311\Scripts\python.exe"

Set-Location $repoRoot

Write-Host "Checking git status..."
git status --short

Write-Host "Checking that .env files are not tracked..."
$trackedEnv = git ls-files ".env" ".env.*" "dashboard/.env" "dashboard/.env.*"
$trackedEnv = @($trackedEnv | Where-Object { $_ -and $_ -notlike "*.env.example" })
if ($trackedEnv.Count -gt 0) {
    Write-Error "Tracked env files found: $($trackedEnv -join ', ')"
}

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

Write-Host "Release checks completed."
