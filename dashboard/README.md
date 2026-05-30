# VulScan Dashboard

The VulScan dashboard is a local React + Vite + TypeScript interface for authorised vulnerability management workflows. It presents API health, scan jobs, findings, risk overview, trends, reports, remediation tracking, bug bounty scope management, settings, demo mode, portfolio mode, and screenshot mode.

The dashboard is local development tooling. It does not collect credentials and does not include exploit, brute-force, credentialed scan, password, token, private key, command execution, or automatic remediation controls.

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

## Bug Bounty Scope Manager

The Bug Bounty section lists local scope files from `data/bug_bounty`, shows program metadata, in-scope and out-of-scope rules, forbidden actions, allowed and disallowed test types, rate limits, and a target scope validation panel.

Version 18.0 does not launch scans from this panel. If a target is out of scope, the panel shows a clear warning.

## Safety Note

The dashboard creates safe API scan jobs only. Credentialed Linux and Windows scans remain CLI-only. Remediation updates are local tracking records only and do not patch systems, run commands, restart services, or modify targets.
