# VulScan Dashboard

Version 16.4 adds a Trends View for completed scan jobs with prioritisation trend data. The dashboard is for local development only and should be used with the API bound to `127.0.0.1`.

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

## Review Risk Overview

Select a completed job to populate the Risk Overview. If no job is selected, the dashboard will use the latest completed job when result and finding data can be loaded.

The Risk Overview uses loaded findings and the selected job result data to show:

- Total findings, Critical/High findings, Fix First findings, highest priority score, highest risk score, exploit metadata count, CVE finding count, and asset criticality.
- Severity, priority, and source distributions.
- Top risk findings sorted by priority score, risk score, then severity fallback.
- Trend summary when scans were created with priority trends and saved history.
- Asset context when scans use asset criticality data.

Trend cards need scans created with priority trends and saved history, such as `--priority-trends` and `--save-db` in the CLI flow. Asset context cards need asset criticality data. The Risk Overview is read-only and includes no exploit or credential controls.

## Review Trends

Select a completed job with loaded result data to populate the Trends View. Trends require scans run with `--priority-trends` and `--save-db`.

The first scan for a target becomes the trend baseline. The second and later scans can show whether prioritised risk is improved, worsened, stable, or still baseline. Trend tables show new findings, resolved findings, priority increases, priority decreases, new Fix First findings, resolved Fix First findings, and persisting Fix First findings when those details are present.

Trend matching is based on stable finding keys. It is useful for remediation tracking, but renamed findings, changed evidence, or scanner improvements may still need human review.

The Trends View is read-only and local. It does not add exploit, brute-force, credential, password, token, private key, or deployment controls.

## Review Vulnerabilities

Select a completed job, then load findings. The vulnerability list supports:

- Client-side search across loaded finding text.
- API-backed filters for severity, source, category, priority, minimum priority score, and minimum risk score.
- API-backed sorting by severity, risk score, priority score, title, source, and category.
- API-backed pagination with page sizes of 10, 20, and 50.
- Detail view for evidence, impact, recommendations, verification, prioritisation, CVE/CVSS/EPSS metadata, exploit metadata indicators, affected URLs, asset criticality, and remediation status where available.

The vulnerability list is read-only. It does not add exploit or credential controls.

## Build Check

```powershell
cd dashboard
npm run build
```

## Scope

The Version 16.4 dashboard shows API health, version metadata, safe scan job creation, recent jobs, selected job details, result summaries, Risk Overview charts, Trends View, recent scans, a vulnerability list, and finding details. It does not add public deployment, exploitation, exploit download buttons, brute forcing, credential collection, credentialed scan forms, password fields, or stored secrets.
