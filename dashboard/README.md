# VulScan Dashboard

The VulScan dashboard is a local React + Vite + TypeScript interface for authorised vulnerability management and Bug Intelligence workflows.

It presents API health, scan jobs, findings, risk overview, trends, Evidence & Reports, remediation tracking, Program Scope, Recon Intelligence, Endpoint Intelligence, Safe Validation, Submission Tracker, Duplicate Detection, Performance Metrics, settings, demo mode, portfolio mode, and screenshot mode.

## Safety Note

The dashboard is local development tooling. It does not collect credentials, does not expose exploit buttons, does not request external platform API tokens, and does not submit reports to external platforms.

## Pages And Sections

- Overview
- Jobs
- Vulnerabilities
- Risk
- Trends
- Evidence & Reports
- Remediation
- Bug Intelligence Workflow
- Performance Metrics
- Program Scope
- Recon Intelligence
- Endpoint Intelligence
- Safe Validation
- Submission Tracker
- Duplicate Detection
- OWASP Top 10
- Settings

## Requirements

- Node.js and npm
- VulScan backend API running locally for live data
- Optional `VITE_VULSCAN_API_KEY` when the backend is started with API key protection

## Start The API

From the project root:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main api
```

With local API key protection:

```powershell
$env:VULSCAN_API_KEY="change-this-local-dev-key"
.\.venv311\Scripts\python.exe -m scanner.main api --require-api-key
```

## Install And Run

```powershell
cd dashboard
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

## Build

```powershell
cd dashboard
npm run build
```

## Environment Variables

Create `dashboard/.env` from `dashboard/.env.example` for local settings. Do not commit `.env`.

```text
VITE_VULSCAN_API_URL=http://127.0.0.1:8088
VITE_VULSCAN_API_KEY=
VITE_VULSCAN_DEMO_MODE=false
VITE_VULSCAN_PORTFOLIO_MODE=false
VITE_VULSCAN_SCREENSHOT_MODE=false
```

## API Key Setup

If the backend is started with `--require-api-key`, set `VITE_VULSCAN_API_KEY` to the same local development key as `VULSCAN_API_KEY`.

The dashboard sends the key as `X-VulScan-API-Key` only when configured. It shows only whether a key is configured and never displays the value.

## Demo Mode

Demo mode uses fake sample jobs, scans, findings, reports, risk data, trends, remediation records, Bug Intelligence data, Duplicate Detection data, and Performance Metrics.

```text
VITE_VULSCAN_DEMO_MODE=true
```

No real target is scanned in demo mode.

## Portfolio Mode

Portfolio mode adds presentation framing for GitHub screenshots and demos.

```text
VITE_VULSCAN_PORTFOLIO_MODE=true
```

Use it with demo mode for public screenshots.

## Screenshot Mode

Screenshot mode adds a compact capture guide.

```text
VITE_VULSCAN_SCREENSHOT_MODE=true
```

Use screenshot mode with demo mode and portfolio mode. Do not show real targets, client data, API keys, tokens, `.env` files, or private paths.

## Bug Intelligence Workflow

The workflow view connects:

```text
Program Scope -> Recon Intelligence -> Endpoint Intelligence -> OWASP Mapping -> Safe Validation -> Evidence -> Security Report -> Submission -> Retest -> Metrics
```

The workflow view is tracking and review support only. It does not perform exploitation, payload checks, credential attacks, or automatic external submission.

## Performance Metrics

Performance Metrics show local workflow progress, quality indicators, acceptance rate, duplicate rate, retest outcomes, Program Performance, vulnerability classes, monthly activity, and bounty totals where manually tracked.

Metrics are local-only and do not access external platforms, browser sessions, cookies, tokens, or credentials.

## Troubleshooting API Connection

- Confirm the API is running at `http://127.0.0.1:8088`.
- Confirm `VITE_VULSCAN_API_URL` matches the backend URL.
- If API key protection is enabled, confirm `VITE_VULSCAN_API_KEY` matches `VULSCAN_API_KEY`.
- Restart `npm run dev` after changing `.env`.
- Use demo mode when the API is offline and you only need screenshots.

## Screenshot Guidance

See [../docs/SCREENSHOT_CHECKLIST.md](../docs/SCREENSHOT_CHECKLIST.md).
## OWASP Assessment

Version 20.0 adds an OWASP Assessment view for OWASP Top 10:2025 evidence, category results, coverage matrix, manual validation requirements, coverage gaps, and the existing OWASP indicator mapping. Use `/owasp/assessment/rules` and `/owasp/assessment/build`, or select a job result that already includes `owasp_assessment_summary`.
# A04 Cryptographic Failures View

The OWASP Assessment dashboard renders A04 Cryptographic Failures evidence when a selected scan result includes `a04_crypto_summary`, `a04_crypto_evidence`, and optional `a04_tls_metadata`. The view shows summary cards, transport evidence, cookie security evidence, TLS metadata, mixed content indicators, recommendations, limitations, indicator confidence, and manual validation notes.

Build check:

```powershell
npm run build
```

# A07 Authentication Failures View

The OWASP Assessment dashboard renders A07 Authentication Failures evidence when a selected scan result includes `a07_authentication_summary` and `a07_authentication_evidence`. The view shows summary cards, authentication endpoint indicators, session cookie evidence, auth form indicators, rate-limit header indicators, recommendations, limitations, indicator confidence, and a manual validation checklist.
