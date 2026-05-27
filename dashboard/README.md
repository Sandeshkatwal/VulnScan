# VulScan Dashboard

Version 16.1 adds local dashboard scan job controls for the VulScan API. It is for local development only and should be used with the API bound to `127.0.0.1`.

## Start The API

From the project root:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main api
```

With API key protection:

```powershell
$env:VULSCAN_API_KEY="change-this-local-dev-key"
.\.venv311\Scripts\python.exe -m scanner.main api --require-api-key
```

The API runs at:

```text
http://127.0.0.1:8088
```

## Configure The Dashboard

Copy `dashboard/.env.example` to `dashboard/.env` for local settings. Do not commit `.env`.

```text
VITE_VULSCAN_API_URL=http://127.0.0.1:8088
VITE_VULSCAN_API_KEY=
```

If the backend is running with `--require-api-key`, set `VITE_VULSCAN_API_KEY` to the same local development key. The dashboard sends `X-VulScan-API-Key` only when that value exists.

## Start The Dashboard

```powershell
cd dashboard
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

## Create A Safe Scan Job

Use the dashboard form to create a safe API scan job. The form sends `POST /scans` with `scan_mode` hard-coded to `safe` and supports only:

- `target`
- `json_report`
- `html_report`
- `save_db`
- `prioritise`
- `fix_first_dashboard`

The dashboard can then refresh job status, load result summaries, and load/filter job findings for completed jobs.

The dashboard does not support credentialed scans, SSH credentials, Windows credentials, API key entry, token entry, private key entry, exploit options, brute forcing, or active web attack options.

## Build Check

```powershell
cd dashboard
npm run build
```

## Scope

The Version 16.1 dashboard shows API health, version metadata, safe scan job creation, recent jobs, selected job details, result summaries, recent scans, and selected job findings with safe filters. It does not add public deployment, exploitation, brute forcing, credential collection, credentialed scan forms, password fields, or stored secrets.
