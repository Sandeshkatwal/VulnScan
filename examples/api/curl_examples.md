# VulScan API curl Examples

These examples use the local API at `http://127.0.0.1:8088`. Use only for authorised local testing.

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
curl http://127.0.0.1:8088/health
```

## Create Scan Job

```powershell
curl -X POST http://127.0.0.1:8088/scans -H "Content-Type: application/json" -d "{\"target\":\"127.0.0.1\",\"scan_mode\":\"safe\",\"json_report\":true,\"html_report\":false,\"save_db\":true,\"vuln_intel\":false,\"prioritise\":true,\"fix_first_dashboard\":true}"
```

With API key:

```powershell
curl -X POST http://127.0.0.1:8088/scans -H "Content-Type: application/json" -H "X-VulScan-API-Key: change-this-local-dev-key" -d "{\"target\":\"127.0.0.1\",\"scan_mode\":\"safe\",\"json_report\":true,\"html_report\":false,\"save_db\":true}"
```

## List Jobs

```powershell
curl http://127.0.0.1:8088/jobs
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/jobs
```

## Check Job Status

```powershell
curl http://127.0.0.1:8088/jobs/JOB_ID
```

## Get Job Result

```powershell
curl http://127.0.0.1:8088/jobs/JOB_ID/result
```

## Get Job Findings

```powershell
curl http://127.0.0.1:8088/jobs/JOB_ID/findings
```

## Filtering And Pagination

```powershell
curl "http://127.0.0.1:8088/jobs?status=completed&limit=10"
curl "http://127.0.0.1:8088/jobs?target=127.0.0.1&limit=10"
curl "http://127.0.0.1:8088/jobs/JOB_ID/findings?severity=High"
curl "http://127.0.0.1:8088/jobs/JOB_ID/findings?priority_label=Fix%20First&compact=true"
curl "http://127.0.0.1:8088/jobs/JOB_ID/findings?min_priority_score=75&sort_by=priority_score&sort_order=desc"
```

## Export Findings

```powershell
curl "http://127.0.0.1:8088/exports/findings?format=csv&severity=Medium"
```
