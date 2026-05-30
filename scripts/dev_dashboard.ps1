$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$dashboard = Join-Path $repoRoot "dashboard"

if (-not (Test-Path (Join-Path $dashboard "package.json"))) {
    Write-Error "Dashboard package.json not found."
}

Set-Location $dashboard
npm run dev
