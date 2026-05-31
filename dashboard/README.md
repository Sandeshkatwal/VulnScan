# VulScan Dashboard

The VulScan dashboard is a local React + Vite + TypeScript interface for authorised vulnerability management workflows. It presents API health, scan jobs, findings, risk overview, trends, Evidence & Reports, remediation tracking, Bug Intelligence, Program Scope, Recon Intelligence, endpoint discovery, Safe Validation, Submission Tracker, settings, demo mode, portfolio mode, and screenshot mode.

The dashboard is local development tooling. It does not collect credentials and does not include exploit, brute-force, credentialed scan, password, token, private key, command execution, or automatic remediation controls.

## Endpoint Discovery

The **Endpoints** section under Bug Intelligence accepts one URL or path per line,
an optional base URL for path-only entries, a local scope file, and scope
enforcement. It returns endpoint candidates, parameter intelligence, skipped
URLs, and summary counts.

Parameter candidates are not confirmed vulnerabilities. The dashboard does not
add payload testing, exploit, form submission, or brute-force controls.

## OWASP Top 10

The **OWASP Top 10** section shows OWASP Top 10:2025 indicator mapping for the
selected job result when available. It can also map the loaded result through
the local API without running any new tests.

The view uses the terms Indicator, Candidate, and Manual validation required.
It must not be interpreted as confirmed OWASP vulnerability evidence.

## Safe Validation

The **Safe Validation** section under Bug Intelligence runs limited non-destructive
checks through the local API. It supports only reflected marker observation,
same-origin redirect indicators, CORS header observation, directory listing
indicators, known public default files, and HTTP `OPTIONS` method observation.

The view does not provide SQLi, XSS, SSRF, payload, exploit, upload, auth
bypass, brute-force, form submission, or destructive method controls. Results
are indicators only and require manual validation.

## Requirements

- Node.js LTS
- npm
- VulScan backend API running locally for live data

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
npm run build
```

## Environment Variables

Copy `.env.example` to `.env` for local settings. Do not commit `.env`.

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

Set:

```text
VITE_VULSCAN_DEMO_MODE=true
```

Demo mode uses fake sample jobs, scans, findings, reports, risk data, trends, remediation records, and asset context. No real target is scanned in demo mode.

## Portfolio Mode

Set:

```text
VITE_VULSCAN_PORTFOLIO_MODE=true
```

Portfolio mode adds presentation framing for the implemented platform while keeping local-only and demo safety notices visible.

## Screenshot Mode

Set:

```text
VITE_VULSCAN_SCREENSHOT_MODE=true
```

Screenshot mode adds a compact capture guide. Use it with demo mode and portfolio mode for portfolio screenshots.

## Troubleshooting API Connection

- Confirm the API is running at `http://127.0.0.1:8088`.
- Open `http://127.0.0.1:8088/health` in a browser or run `curl http://127.0.0.1:8088/health`.
- Check `VITE_VULSCAN_API_URL` matches the backend URL.
- If the protected endpoint test fails, confirm `VITE_VULSCAN_API_KEY` matches `VULSCAN_API_KEY`.
- Restart `npm run dev` after changing `.env`.
- Use demo mode when the backend is not running and you only need screenshots.

## Program Scope Manager

The Program Scope section lists local scope files from `data/bug_bounty`, shows program metadata, in-scope and out-of-scope rules, forbidden actions, allowed and disallowed test types, rate limits, and a target scope validation panel.

If a target is out of scope, the panel shows a clear warning.

## Recon Intelligence

The Recon section accepts manually provided targets, selects a local scope file, defaults to scope enforcement, and starts safe HTTP/HTTPS metadata probing through the local API.

Recon results show input counts, in-scope and out-of-scope counts, live assets, errors, skipped targets, status codes, page titles, server headers, technology hints, response times, and final URLs.

The recon UI does not include subdomain brute forcing, wordlists, exploit actions, payload controls, credential collection, or public scanning defaults.

## Submission Tracker

The Submission Tracker section provides local Submission and Retest Tracking for Security Finding Reports. It includes summary cards, a submission form, status updates, redacted notes, timeline events, and retest checklist records.

Tracking is local only. VulScan does not submit reports to external platforms, does not integrate platform API tokens, and does not store platform credentials.

## Safety Note

The dashboard creates safe API scan jobs only. Credentialed Linux and Windows scans remain CLI-only. Remediation updates are local tracking records only and do not patch systems, run commands, restart services, or modify targets.
