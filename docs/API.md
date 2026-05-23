# VulScan API

Version 15.2 adds API key protection to the local FastAPI API for authorised VulScan workflows.

The API binds to `127.0.0.1` by default, does not enable broad CORS, does not expose credentialed SSH or Windows scans, and does not accept passwords, tokens, private keys, API keys, authorization headers, or secrets in scan requests.

## API Key Protection

Set the API key in the `VULSCAN_API_KEY` environment variable. Do not hard-code it, print it, store it in reports, or commit it to Git.

Temporary key for the current PowerShell session:

```powershell
$env:VULSCAN_API_KEY="change-this-local-dev-key"
```

Start the API and require a configured key:

```powershell
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
```

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

If `save_db` is `false`, the response returns the current scan summary, but `GET /scans/{scan_id}` may not be able to retrieve it later.

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
- Credentialed SSH and Windows scans are not exposed through the API.
- API request models do not include password, token, secret, private key, API key, bearer, or authorization fields.
- The API authentication header is checked separately and is not copied into scan request data.
- API responses use friendly errors and avoid raw tracebacks or submitted secret-like values.
