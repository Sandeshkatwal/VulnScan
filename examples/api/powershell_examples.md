# VulScan API PowerShell Examples

These examples use the local API at `http://127.0.0.1:8088` for authorised local testing.

## Start API

```powershell
.\.venv311\Scripts\python.exe -m scanner.main api
```

With API key protection:

```powershell
$env:VULSCAN_API_KEY="change-this-local-dev-key"
.\.venv311\Scripts\python.exe -m scanner.main api --require-api-key
```

## Health Check

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8088/health" -Method Get
```

## API Key Header

```powershell
$headers = @{
    "X-VulScan-API-Key" = $env:VULSCAN_API_KEY
}
```

## Create Scan Job

```powershell
$body = @{
    target = "127.0.0.1"
    scan_mode = "safe"
    json_report = $true
    html_report = $false
    save_db = $true
    vuln_intel = $false
    prioritise = $true
    fix_first_dashboard = $true
} | ConvertTo-Json

$job = Invoke-RestMethod `
    -Uri "http://127.0.0.1:8088/scans" `
    -Method Post `
    -ContentType "application/json" `
    -Headers $headers `
    -Body $body

$jobId = $job.job_id
```

## Poll Job Status

```powershell
do {
    Start-Sleep -Seconds 2
    $status = Invoke-RestMethod -Uri "http://127.0.0.1:8088/jobs/$jobId" -Headers $headers
    $status.status
} while ($status.status -in @("queued", "running"))
```

## Get Findings

```powershell
$findings = Invoke-RestMethod -Uri "http://127.0.0.1:8088/jobs/$jobId/findings?limit=20" -Headers $headers
$findings.findings
```

## Filtering And Pagination

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8088/jobs?status=completed&limit=10" -Headers $headers
Invoke-RestMethod -Uri "http://127.0.0.1:8088/jobs/$jobId/findings?priority_label=Fix%20First&compact=true" -Headers $headers
Invoke-RestMethod -Uri "http://127.0.0.1:8088/exports/findings?format=csv&severity=Medium" -Headers $headers
```
