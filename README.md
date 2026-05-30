# VulScan

VulScan is a local authorised vulnerability scanning and vulnerability management platform. It is designed for defensive assessment, reporting, triage, and remediation tracking on systems you own or have explicit permission to assess.

## Safety Statement

Use VulScan only on systems and web applications you own or have explicit written permission to test. The project is intentionally scoped for safe local operation and must not be used for exploitation, credential attacks, brute forcing, destructive checks, or unauthorised scanning.

## Feature Overview

- Discovery Engine for safe TCP connect scanning and service identification.
- Credentialed Linux Audit using explicit SSH credentials and read-only checks.
- Credentialed Windows Audit using safe reachability checks and optional read-only WinRM indicators.
- Passive Web DAST for bounded crawling, headers, cookies, forms, robots.txt, sitemap, scope, and politeness reporting.
- Vulnerability Intelligence with local rules, local CVE-style feeds, local EPSS metadata, and local exploit-availability metadata as prioritisation signals only.
- Prioritisation and Fix-First Dashboard data for remediation triage.
- Local FastAPI API with jobs, filtering, pagination, report access, remediation tracking, and optional API key protection.
- React Dashboard for jobs, findings, risk overview, trends, reports, settings, remediation, demo mode, and portfolio mode.
- JSON and HTML reports plus remediation tracking.

## Architecture

```text
VulScan
├── Discovery Engine
├── Credentialed Scan Engine
├── Web DAST Engine
├── Vulnerability Intelligence Engine
├── Prioritisation Engine
├── Storage
├── API
└── Dashboard
```

Data flow:

```text
scan -> findings -> storage -> API -> dashboard
scan -> JSON/HTML reports -> API report endpoints -> dashboard
```

## Quick Start Backend

From the project root in PowerShell:

```powershell
python -m venv .venv311
.\.venv311\Scripts\python.exe -m pip install --upgrade pip
.\.venv311\Scripts\python.exe -m pip install -r requirements.txt
.\.venv311\Scripts\python.exe -m pytest
```

Run a safe localhost scan:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1
```

Run the local API:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main api
```

The API binds to `127.0.0.1:8088` by default.

## Quick Start Dashboard

Start the backend first, then in a second PowerShell terminal:

```powershell
cd dashboard
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

Copy `dashboard/.env.example` to `dashboard/.env` for local dashboard settings. Do not commit `.env`.

## Demo And Portfolio Mode

Dashboard demo mode uses fake sample data only and does not scan a real target. It is intended for screenshots, portfolio presentation, and UI review.

Example dashboard `.env` values:

```text
VITE_VULSCAN_API_URL=http://127.0.0.1:8088
VITE_VULSCAN_API_KEY=
VITE_VULSCAN_DEMO_MODE=true
VITE_VULSCAN_PORTFOLIO_MODE=true
VITE_VULSCAN_SCREENSHOT_MODE=true
```

## Screenshots

Suggested portfolio screenshots:

- Dashboard Overview
- Jobs page
- Vulnerability list
- Finding detail drawer
- Risk overview
- Trends view
- Reports view
- Remediation view
- Settings page
- HTML report output

Use demo mode for screenshots. Do not show secrets, real client data, real API keys, or sensitive local paths.

## Safety And Limitations

- Local and authorised use only.
- API binds to localhost by default.
- Dashboard is local development tooling, not a hardened public deployment.
- Credentialed scans are CLI-only and are not exposed through the API.
- The dashboard does not collect credentials.
- Passive Web DAST does not submit forms, authenticate, fuzz, test SQL injection, test XSS, or execute payloads.
- Vulnerability intelligence is local-file based and does not download exploit code.
- Exploit availability metadata is a prioritisation signal only.
- Remediation features track status only and do not patch systems or run commands.
- Report endpoints serve only JSON and HTML files from the local `reports` directory.
- Do not commit `.env`, API keys, passwords, tokens, private keys, client data, or local databases.

## Documentation

- [Installation](docs/INSTALLATION.md)
- [Usage](docs/USAGE.md)
- [Safety](docs/SAFETY.md)
- [API](docs/API.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Web DAST](docs/WEB_DAST.md)
- [Vulnerability Intelligence](docs/VULNERABILITY_INTELLIGENCE.md)
- [Prioritisation](docs/PRIORITISATION.md)
- [Demo Guide](docs/DEMO_GUIDE.md)
- [Screenshots](docs/SCREENSHOTS.md)
- [Roadmap](docs/ROADMAP.md)
- [Release Checklist](docs/RELEASE_CHECKLIST.md)
- [Dashboard](dashboard/README.md)

## Roadmap

Completed major milestones include the core scanner, storage and reporting, Linux SSH audit, Windows audit, passive Web DAST, vulnerability intelligence, prioritisation engine, API, dashboard, and packaging/release preparation.

Planned areas include persistent dashboard preferences, dashboard authentication hardening, CI/CD testing, Docker or dev container support, more robust CVE feed import, SBOM import, role-based dashboard access, plugin architecture, report PDF export, and optional safe active web checks with strict scope.

## License

License not selected yet.
