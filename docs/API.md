# VulScan API

Version 15.3 adds persistent SQLite API job storage to the local FastAPI API for authorised VulScan workflows.

The API binds to `127.0.0.1` by default, does not enable broad CORS, does not expose credentialed SSH or Windows scans, and does not accept passwords, tokens, private keys, API keys, authorization headers, or secrets in scan requests.

## API Key Protection

Set the API key in the `VULSCAN_API_KEY` environment variable. Do not hard-code it, print it, store it in reports, or commit it to Git.

Temporary key for the current PowerShell session:

```powershell
$env:VULSCAN_API_KEY="change-this-local-dev-key"
```

Start the API and require a configured key:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main api
.\.venv311\Scripts\python.exe -m scanner.main api --require-api-key
```

If `VULSCAN_API_KEY` is set, protected endpoints require one of these headers:

```text
X-VulScan-API-Key: YOUR_KEY
Authorization: Bearer YOUR_KEY
```

If `VULSCAN_API_KEY` is not set, the API can run in local development mode and prints:

```text
API key not configured. Protected endpoints are running in local development mode.
```

Remote binding is still blocked by default. If a non-localhost host is supplied, VulScan requires `--allow-remote-api` and prints a warning. Do not expose the development API publicly.

## Public Endpoints

- `GET /health`
- `GET /version`

These endpoints are available without an API key.

## Protected Endpoints

When `VULSCAN_API_KEY` is configured, these endpoints require a valid key:

- `POST /scans`
- `GET /scans`
- `GET /scans/{scan_id}`
- `GET /scans/{scan_id}/findings`
- `GET /jobs`
- `GET /jobs/{job_id}`
- `GET /jobs/{job_id}/result`
- `GET /jobs/{job_id}/findings`
- `GET /exports/findings`

Missing or incorrect keys return:

```json
{
  "detail": "Invalid or missing API key."
}
```

## Health

```powershell
curl http://127.0.0.1:8088/health
```

Returns:

```json
{
  "status": "ok",
  "scanner": "VulScan"
}
```

## Version

```powershell
curl http://127.0.0.1:8088/version
```

Returns scanner and API version metadata.

## Jobs

```powershell
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/jobs
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/jobs?limit=20&status=completed&target=127.0.0.1"
```

Jobs are stored in the local VulScan SQLite database in the `api_jobs` table. Job metadata can survive API restarts. If the API process stops while jobs are `queued` or `running`, startup marks those jobs as `failed` with `safe_error_code` set to `API_JOB_INTERRUPTED` and the message:

```text
Job was interrupted because the API process stopped before completion.
```

Job rows store safe metadata only: job ID, scan ID, target, status, timestamps, duration, sanitized request fields, result summary, report paths, and safe error fields. API keys and credentials are never stored.

## Start a Safe Scan

```powershell
curl -X POST http://127.0.0.1:8088/scans -H "Content-Type: application/json" -H "X-VulScan-API-Key: change-this-local-dev-key" -d "{\"target\":\"127.0.0.1\",\"scan_mode\":\"safe\",\"json_report\":true,\"html_report\":false,\"save_db\":true}"
```

Supported request fields:

- `target`
- `scan_mode`, currently only `safe`
- `json_report`
- `html_report`
- `save_db`
- `vuln_intel`
- `prioritise`
- `fix_first_dashboard`

The API scan can run the simple safe TCP scan and optional local vulnerability intelligence and prioritisation. It does not expose SSH credentials, Windows credentials, credentialed scans, active Web DAST, exploit checks, live attack checks, or internet feed fetching.

`POST /scans` creates a persistent API job and starts the safe scan in a background task. The response includes a `job_id` plus the existing scan response fields. Use `GET /jobs/{job_id}` to check status.

## Get Job

```powershell
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/jobs/JOB_ID
```

Returns persistent job metadata:

```json
{
  "job_id": "JOB_ID",
  "scan_id": "SCAN_ID",
  "target": "127.0.0.1",
  "status": "completed",
  "created_at": "...",
  "started_at": "...",
  "completed_at": "...",
  "duration_seconds": 1.23,
  "result_summary": {},
  "result_path": "reports/example.json",
  "html_report_path": null,
  "error_message": null,
  "safe_error_code": null
}
```

## Get Job Result

```powershell
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/jobs/JOB_ID/result
```

For completed jobs, VulScan first tries the saved JSON report path. If that is unavailable but `scan_id` exists, VulScan tries the saved scan history in SQLite. If neither is available, the endpoint returns:

```text
Job completed but result payload is no longer available.
```

## Get Job Findings

```powershell
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/jobs/JOB_ID/findings
```

Findings are loaded from the same result sources. If they are unavailable, the endpoint returns a friendly message and an empty findings list.

If `save_db` is `false`, job metadata is still persisted, but later result retrieval depends on the JSON report path still existing.

## List Scans

```powershell
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/scans
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/scans?limit=5&target=127.0.0.1"
```

Returns recent saved scans from the local SQLite database.

## Get Scan Result

```powershell
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/scans/SCAN_ID
```

Returns the saved scan result snapshot when available.

## Get Scan Findings

```powershell
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/scans/SCAN_ID/findings
```

Returns saved findings for a scan ID.

## Export Findings

```powershell
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/exports/findings?format=json"
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/exports/findings?format=csv&target=127.0.0.1"
```

The endpoint reuses existing export logic and returns export metadata, including the local export path when a file is written. It does not return huge report or HTML content inline.

## Safety Notes

- API bind host defaults to `127.0.0.1`.
- API keys are read only from `VULSCAN_API_KEY`.
- Do not commit API keys.
- API jobs are stored in the local SQLite database and can survive API restarts.
- Interrupted queued/running jobs are marked failed on startup instead of being silently left running.
- Result payload availability depends on saved JSON reports or saved scan history.
- Credentialed SSH and Windows scans are not exposed through the API.
- API request models do not include password, token, secret, private key, API key, bearer, or authorization fields.
- The API authentication header is checked separately and is not copied into scan request data.
- API responses use friendly errors and avoid raw tracebacks or submitted secret-like values.
