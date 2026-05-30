# VulScan API

The VulScan API is a local FastAPI service for safe scan jobs, saved scan history, findings, reports, exports, remediation tracking, and dashboard integration.

## Start The API

```powershell
.\.venv311\Scripts\python.exe -m scanner.main api
```

With explicit local API key protection:

```powershell
$env:VULSCAN_API_KEY="change-this-local-dev-key"
.\.venv311\Scripts\python.exe -m scanner.main api --require-api-key
```

The API binds to `127.0.0.1:8088` by default. Remote binding requires `--allow-remote-api` and should not be used for public deployment without a security review.

## API Key Setup

Set the key in the `VULSCAN_API_KEY` environment variable. Do not hard-code it, print it, store it in reports, or commit it.

Protected endpoints accept either:

```text
X-VulScan-API-Key: YOUR_KEY
Authorization: Bearer YOUR_KEY
```

`GET /health` and `GET /version` are public. Scan, job, finding, report, export, and remediation endpoints are protected when `VULSCAN_API_KEY` is configured.

## OpenAPI

When the API is running:

- `http://127.0.0.1:8088/docs`
- `http://127.0.0.1:8088/openapi.json`

The schema documents the local API key header but does not include a real key value.

## Dashboard Relationship

The React dashboard reads from the local API and uses:

```text
VITE_VULSCAN_API_URL=http://127.0.0.1:8088
VITE_VULSCAN_API_KEY=
```

If `VITE_VULSCAN_API_KEY` is set, the dashboard sends it as `X-VulScan-API-Key`. The dashboard does not display the key and does not provide credentialed scan or exploit controls.

Allowed dashboard CORS origins are local only:

- `http://localhost:5173`
- `http://127.0.0.1:5173`

## Public Endpoints

- `GET /health`
- `GET /version`

## Scan And Job Endpoints

- `POST /scans`
- `GET /jobs`
- `GET /jobs/{job_id}`
- `GET /jobs/{job_id}/result`
- `GET /jobs/{job_id}/findings`
- `GET /scans`
- `GET /scans/{scan_id}`
- `GET /scans/{scan_id}/findings`

`POST /scans` accepts safe API scan options only, including target, `scan_mode=safe`, JSON/HTML report flags, save-db flag, local vulnerability intelligence, prioritisation, and fix-first dashboard generation. It does not expose SSH credentials, Windows credentials, credentialed scans, active Web DAST, exploit checks, live attack checks, or internet feed fetching.

API jobs are persisted in the local SQLite database. Jobs interrupted by API restart are marked failed with `API_JOB_INTERRUPTED`.

## Filtering And Pagination

List endpoints support pagination metadata with:

- `limit`
- `offset`
- `sort_by`
- `sort_order`

Finding endpoints support filters such as:

- `severity`
- `source`
- `category`
- `priority_label`
- `min_priority_score`
- `min_risk_score`
- `cve`
- `compact=true`

Examples:

```powershell
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/jobs?status=completed&limit=10"
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/jobs/JOB_ID/findings?priority_label=Fix%20First&compact=true"
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/scans?target=127.0.0.1&limit=5"
```

## Report Access Endpoints

- `GET /reports`
- `GET /reports/{report_id}/metadata`
- `GET /reports/{report_id}/download`
- `GET /reports/{report_id}/view`

Report endpoints serve only `.json` and `.html` files from the local `reports` directory. They use safe report IDs, block path traversal, reject raw file paths, and do not serve arbitrary files.

Examples:

```powershell
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/reports
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/reports/REPORT_ID/metadata
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/reports/REPORT_ID/download
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/reports/REPORT_ID/view
```

## Remediation Endpoints

- `GET /remediation`
- `GET /remediation/summary`
- `GET /remediation/{finding_key}`
- `PUT /remediation/{finding_key}`

Remediation endpoints update local tracking fields only: status, owner, due date, and notes. They do not run commands, patch systems, restart services, connect to targets, or modify remote systems.

Example:

```powershell
curl -X PUT http://127.0.0.1:8088/remediation/FINDING_KEY -H "Content-Type: application/json" -H "X-VulScan-API-Key: change-this-local-dev-key" -d "{\"status\":\"in_progress\",\"note\":\"Reviewing remediation options.\"}"
```

Do not include passwords, tokens, API keys, private keys, or secrets in remediation notes.

## Export Endpoint

- `GET /exports/findings`

Examples:

```powershell
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/exports/findings?format=json"
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/exports/findings?format=csv&severity=Medium"
```

## Safety Notes

- API bind host defaults to `127.0.0.1`.
- API keys are read from `VULSCAN_API_KEY`.
- Do not commit API keys or `.env` files.
- Credentialed SSH and Windows scans are not exposed through the API.
- Request models reject credential-like scan fields.
- Report endpoints only serve local `.json` and `.html` reports from `reports`.
- Remediation endpoints are tracking-only.
- API responses avoid raw tracebacks and submitted secret-like values.
