# VulScan API

Version 16.1 adds local dashboard scan job controls for authorised VulScan workflows. The existing API remains local-only and allows narrow CORS access from the Vite development dashboard.

Version 16.7 adds safe report access endpoints for local dashboard report viewing and downloads. Report endpoints serve only `.json` and `.html` files that resolve inside the VulScan `reports` directory.

The API binds to `127.0.0.1` by default, does not enable broad CORS, does not expose credentialed SSH or Windows scans, and does not accept passwords, tokens, private keys, API keys, authorization headers, or secrets in scan requests.

## Local Dashboard

Version 16.1 includes a React + Vite dashboard under `dashboard/`. Start the backend API first:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main api
```

With API key protection:

```powershell
$env:VULSCAN_API_KEY="change-this-local-dev-key"
.\.venv311\Scripts\python.exe -m scanner.main api --require-api-key
```

Then start the dashboard:

```powershell
cd dashboard
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

Dashboard configuration uses Vite environment variables:

```text
VITE_VULSCAN_API_URL=http://127.0.0.1:8088
VITE_VULSCAN_API_KEY=
```

Do not commit `dashboard/.env`. The dashboard includes `X-VulScan-API-Key` only when `VITE_VULSCAN_API_KEY` is set.

The dashboard scan form creates safe jobs through `POST /scans` with `scan_mode` fixed to `safe`. It can refresh job status, load job result summaries, and load/filter findings for completed jobs. It does not support credentialed scans, SSH passwords, Windows passwords, tokens, private keys, API key input fields, exploit options, brute forcing, or active web attack options.

## Local CORS

For the local dashboard only, the API allows these origins:

- `http://localhost:5173`
- `http://127.0.0.1:5173`

Broad wildcard origins are not enabled.

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

## OpenAPI Documentation

When the API is running, interactive documentation and the raw schema are available locally:

- `http://127.0.0.1:8088/docs`
- `http://127.0.0.1:8088/openapi.json`

The OpenAPI schema documents public endpoints without authentication and protected endpoints with the `X-VulScan-API-Key` API key security scheme. It does not include real API key values or credentialed scan examples.

Local client examples:

- `examples/api/curl_examples.md`
- `examples/api/powershell_examples.md`
- `examples/api/python_client.py`

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
- `GET /reports`
- `GET /reports/{report_id}/metadata`
- `GET /reports/{report_id}/download`
- `GET /reports/{report_id}/view`
- `GET /exports/findings`

Missing or incorrect keys return:

```json
{
  "detail": "Invalid or missing API key."
}
```

## Pagination And Filtering

List-style API responses keep their existing top-level keys and add `pagination` and `filters` metadata.

Common query parameters:

- `limit`: default `20`, minimum `1`, maximum `100`
- `offset`: default `0`, minimum `0`
- `sort_by`: endpoint-specific
- `sort_order`: `asc` or `desc`, default `desc`

Pagination metadata includes `limit`, `offset`, `returned`, `total`, `has_next`, `has_previous`, `next_offset`, and `previous_offset`.

## Error Responses

Errors use safe user-facing details and do not include raw tracebacks or submitted secret-like values. Common responses include:

- `400`: invalid request or unsupported option
- `401`: invalid or missing API key
- `404`: local job, scan, or export data was not found
- `422`: request validation failed
- `500`: safe internal API error

Example:

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
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/jobs?limit=20&offset=0"
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/jobs?status=completed&limit=10"
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/jobs?target=127.0.0.1&status=completed"
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/jobs?sort_by=duration_seconds&sort_order=desc"
```

Supported filters and sorting:

- `status`
- `target`
- `sort_by`: `created_at`, `updated_at`, `completed_at`, `duration_seconds`, `status`, `target`
- `sort_order`: `asc` or `desc`

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
  "result_download_url": "/reports/REPORT_ID/download",
  "html_report_path": null,
  "html_view_url": null,
  "html_download_url": null,
  "error_message": null,
  "safe_error_code": null
}
```

When saved report paths can be mapped safely into the local `reports` directory, job responses include report URLs. If mapping is not possible, the original path fields remain and URL fields are omitted or `null`.

## Reports

```powershell
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/reports
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/reports?type=html&limit=10"
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/reports/REPORT_ID/metadata
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/reports/REPORT_ID/download
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/reports/REPORT_ID/view
```

`GET /reports` lists report files from the local `reports` directory. Supported query parameters are:

- `limit`: default `20`, minimum `1`, maximum `100`
- `offset`: default `0`
- `type`: `json`, `html`, or `all`
- `target`: optional target filter

Each report entry includes `report_id`, `filename`, `type`, `target`, `created_at`, `size_bytes`, `download_url`, and `view_url`. `GET /reports/{report_id}/metadata` returns one entry. `GET /reports/{report_id}/download` returns a JSON or HTML report as an attachment. `GET /reports/{report_id}/view` returns an HTML response for HTML reports and a JSON response for JSON reports.

Report IDs are safe URL identifiers that map only to known files under the configured reports directory. The API rejects path traversal, raw file paths, unknown IDs, unsupported suffixes, and files outside `reports`. It serves only `.json` and `.html` report files. When `VULSCAN_API_KEY` is configured, report endpoints require the same API key protection as jobs and scans.

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
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/jobs/JOB_ID/findings?severity=High"
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/jobs/JOB_ID/findings?priority_label=Fix%20First&compact=true"
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/jobs/JOB_ID/findings?min_priority_score=75&sort_by=priority_score&sort_order=desc"
```

Findings are loaded from the same result sources. If they are unavailable, the endpoint returns a friendly message and an empty findings list.

If `save_db` is `false`, job metadata is still persisted, but later result retrieval depends on the JSON report path still existing.

Finding filters:

- `severity`
- `source`
- `category`
- `priority_label`
- `min_priority_score`
- `min_risk_score`
- `cve`
- `sort_by`: `severity`, `risk_score`, `priority_score`, `title`, `source`, `category`
- `sort_order`: `asc` or `desc`
- `compact=true`: returns title, severity, source, category, risk score, priority score, priority label, and recommendation only.

## List Scans

```powershell
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/scans
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/scans?limit=5&offset=0&target=127.0.0.1"
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/scans?sort_by=scan_time&sort_order=desc"
```

Returns recent saved scans from the local SQLite database. Supported scan filters and sorting are `target`, `sort_by=scan_time|target|duration_seconds`, and `sort_order=asc|desc`.

## Get Scan Result

```powershell
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/scans/SCAN_ID
```

Returns the saved scan result snapshot when available.

## Get Scan Findings

```powershell
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/scans/SCAN_ID/findings
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/scans/SCAN_ID/findings?severity=Medium&compact=true"
```

Returns saved findings for a scan ID. It supports the same finding filters, sorting, pagination, and `compact=true` option as `GET /jobs/{job_id}/findings`.

## Export Findings

```powershell
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/exports/findings?format=json"
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/exports/findings?format=csv&target=127.0.0.1"
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/exports/findings?format=csv&severity=Medium"
```

The endpoint reuses existing export logic and returns export metadata, including the local export path when a file is written. It supports `target`, `severity`, `source`, `category`, `priority_label`, `min_priority_score`, `min_risk_score`, `limit`, and `offset`. It does not return huge report or HTML content inline.

## Safety Notes

- API bind host defaults to `127.0.0.1`.
- API keys are read only from `VULSCAN_API_KEY`.
- Do not commit API keys.
- API jobs are stored in the local SQLite database and can survive API restarts.
- Interrupted queued/running jobs are marked failed on startup instead of being silently left running.
- Job, scan, finding, and findings export endpoints support filtering and pagination.
- `compact=true` reduces finding responses for dashboard-style views.
- OpenAPI docs are available locally at `/docs` and `/openapi.json`.
- Client examples are available under `examples/api`.
- Result payload availability depends on saved JSON reports or saved scan history.
- Report view and download endpoints serve only `.json` and `.html` files inside the local `reports` directory.
- Report endpoints do not accept raw file paths and block path traversal.
- Credentialed SSH and Windows scans are not exposed through the API.
- API request models do not include password, token, secret, private key, API key, bearer, or authorization fields.
- The API authentication header is checked separately and is not copied into scan request data.
- API responses use friendly errors and avoid raw tracebacks or submitted secret-like values.
