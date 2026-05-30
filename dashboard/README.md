# VulScan Dashboard

Version 16.9 adds final dashboard polish, demo data mode, portfolio mode, screenshot mode, and presentation-friendly empty states. The dashboard is for local development only and should be used with the API bound to `127.0.0.1`.

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
VITE_VULSCAN_DEMO_MODE=false
VITE_VULSCAN_PORTFOLIO_MODE=false
VITE_VULSCAN_SCREENSHOT_MODE=false
```

If the backend is running with `--require-api-key`, set `VITE_VULSCAN_API_KEY` to the same local development key. The dashboard sends `X-VulScan-API-Key` only when that value exists.

## Demo And Portfolio Modes

Demo mode is enabled with:

```text
VITE_VULSCAN_DEMO_MODE=true
```

Demo mode uses fake sample data only and clearly labels the dashboard with:

```text
Demo Mode: sample data only. No real target was scanned.
```

Demo records use safe sample targets such as `127.0.0.1`, `demo-linux.local`, `demo-windows.local`, and `demo-web.local`. They include fake jobs, scans, findings, risk data, trend data, report metadata, remediation records, and asset context. Demo report paths such as `reports\demo_report.json` and `reports\demo_report.html` are display-only unless a real backend report endpoint provides a matching file.

Portfolio mode is enabled with:

```text
VITE_VULSCAN_PORTFOLIO_MODE=true
```

Portfolio mode adds a polished hero, project summary, architecture summary, and footer while keeping local-only and demo labels visible.

Screenshot mode is enabled with:

```text
VITE_VULSCAN_SCREENSHOT_MODE=true
```

Screenshot mode adds a compact screenshot guide and keeps presentation-critical labels visible. It does not hide local-only or demo safety notices.

Suggested screenshot flow:

1. Start the dashboard.
2. Enable demo mode.
3. Open Overview.
4. Open Risk.
5. Open Vulnerabilities.
6. Open Reports.
7. Open Remediation.
8. Capture screenshots.

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

## Dashboard Sections

Version 16.6 organises the dashboard into:

- Overview: API status, main metric cards, recent jobs, recent scans, and quick risk summary.
- Jobs: safe scan creation, recent jobs, selected job details, result loading, and findings loading.
- Vulnerabilities: finding filters, findings table, pagination, and finding detail view.
- Risk: risk overview, severity distribution, priority distribution, source distribution, and top risk findings.
- Trends: prioritisation trends, trend details, and comparison panels.
- Reports: saved report paths, report metadata, safe copy controls, and API-backed view/download actions when report URLs are available.
- Remediation: tracking-only remediation status, owner, due date, and notes.
- Settings: API URL, API key configured/not configured status, connection tests, protected endpoint test, refresh interval preference, local dashboard mode, backend docs, and OpenAPI links.

The dashboard keeps selected job, loaded result, loaded findings, and filter state while switching sections. API keys are configured through `.env`; the dashboard shows only whether a key is configured and never displays the key value.

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

## Review Reports

The Reports View reads completed jobs and the safe `GET /reports` index from the API. It shows report metadata returned by job fields such as `result_path`, `html_report_path`, `result_summary`, `job_id`, `scan_id`, `target`, and completion time, plus safe report URLs when the backend can map the report path into the local `reports` directory.

Use the Reports View to:

- Review latest completed jobs that produced JSON or HTML report paths.
- View HTML reports through the local API when `html_view_url` is available.
- Download JSON or HTML reports through authenticated API requests when download URLs are available.
- Copy JSON report paths, HTML report paths, job IDs, and scan IDs.
- Load result metadata for prioritisation, fix-first dashboard, trends, vulnerability intelligence, Web DAST, and asset context summaries when available.
- Load findings metadata for the selected report job.

Local HTML report files may still need to be opened through File Explorer or PowerShell if API report URLs are unavailable. Browsers often block direct local file access from `localhost`. For example:

```powershell
Start-Process .\reports\REPORT_FILE.html
```

Report endpoints serve only `.json` and `.html` files from the VulScan `reports` directory. They do not accept raw file paths and do not serve arbitrary files outside that directory. If the API key is configured, the dashboard uses authenticated fetch downloads and never logs or displays the key.

## API Connection Manager

The Settings page shows the configured API base URL, whether an API key is configured, and local dashboard mode. It includes buttons to test `/health`, `/version`, and a protected `GET /jobs?limit=1` request. If the protected test fails, check that `VITE_VULSCAN_API_KEY` matches the backend `VULSCAN_API_KEY`.

Refresh is manual by default. The optional refresh interval preference is stored in local browser storage as `refreshIntervalSeconds`; it does not expose secrets and does not enable aggressive automatic polling.

## Review Vulnerabilities

Select a completed job, then load findings. The vulnerability list supports:

- Client-side search across loaded finding text.
- API-backed filters for severity, source, category, priority, minimum priority score, and minimum risk score.
- API-backed sorting by severity, risk score, priority score, title, source, and category.
- API-backed pagination with page sizes of 10, 20, and 50.
- Detail view for evidence, impact, recommendations, verification, prioritisation, CVE/CVSS/EPSS metadata, exploit metadata indicators, affected URLs, asset criticality, and remediation status where available.

The vulnerability list is read-only. It does not add exploit or credential controls.

## Track Remediation

Version 16.8 adds a Remediation section for local tracking only. It shows summary counts for Open, In Progress, Fixed, Accepted Risk, and False Positive records, plus a filterable table with title, target, severity, priority, source, owner, due date, and update time.

You can update a finding status, owner, due date, and note from the Remediation section or from the finding detail drawer when a finding has a `finding_key`. Status updates are stored in the local SQLite remediation tables only.

VulScan does not automatically patch systems, restart services, execute commands, connect to targets, or modify remote systems. Remediation notes should not contain passwords, tokens, API keys, private keys, secrets, or credential material. API key protection applies when configured.

## Build Check

```powershell
cd dashboard
npm run build
```

## Architecture Summary

The dashboard portfolio view summarises these project areas:

- Discovery Engine: implemented.
- Credentialed Scan Engine: implemented.
- Web DAST Engine: foundation.
- Vulnerability Intelligence Engine: implemented.
- Prioritisation Engine: implemented.
- Storage: implemented.
- API: implemented.
- Dashboard: in progress.

## Scope

The Version 16.9 dashboard shows API health, version metadata, sidebar navigation, safe scan job creation, recent jobs, selected job details, result summaries, Risk Overview charts, Trends View, Reports View with safe API report access, remediation tracking, portfolio/demo presentation views, recent scans, a vulnerability list, settings, and finding details. It does not add public deployment, exploitation, exploit download buttons, brute forcing, credential collection, credentialed scan forms, password fields, command execution, automatic patching, or stored secrets.
