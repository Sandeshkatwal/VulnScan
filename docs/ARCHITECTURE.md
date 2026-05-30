# VulScan Architecture

VulScan is a local authorised vulnerability scanning and vulnerability management platform. The architecture separates evidence collection, enrichment, prioritisation, storage, API access, and dashboard presentation.

## High-Level Architecture

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

## Backend Modules

- `scanner.main`: Typer CLI commands for scans, web scans, API startup, history, diffing, remediation, assets, and exports.
- `scanner.port_scan` and service detection modules: safe TCP connect scanning and static service identification.
- `scanner.ssh_audit`, `scanner.package_audit`, `scanner.linux_config_audit`: read-only Linux credentialed audit checks.
- `scanner.windows_audit`, `scanner.windows_result`, `scanner.windows_*`: Windows reachability, optional WinRM validation, and read-only indicators.
- `scanner.web_*`: passive Web DAST crawling, scope, rate limiting, robots, sitemap, headers, cookies, forms, and passive summary reporting.
- `scanner.software_inventory`, `scanner.vuln_intel`, `scanner.cve_feed`, `scanner.epss_importer`, `scanner.exploit_metadata`: local vulnerability intelligence and metadata enrichment.
- `scanner.risk_score`, `scanner.asset_criticality`, `scanner.prioritisation`, `scanner.prioritisation_report`, `scanner.prioritisation_trends`: risk scoring, business context, fix-first reporting, and trend tracking.
- `scanner.database`, `scanner.history`, `scanner.remediation`, `scanner.assets`, `scanner.exporter`: local SQLite storage, remediation records, asset inventory, and exports.
- `scanner.api_app`, `scanner.api_runner`, `scanner.api_jobs`, `scanner.api_job_store`, `scanner.api_filters`, `scanner.api_reports`, `scanner.api_remediation`, `scanner.api_security`: local FastAPI API, persistent jobs, safe report access, filtering, and optional API key protection.
- `scanner.report_json` and `scanner.report_html`: JSON and HTML report generation.

## Dashboard Modules

- `dashboard/src/App.tsx`: top-level application composition.
- `dashboard/src/api/client.ts`: typed API client helpers.
- `dashboard/src/utils`: formatting, demo mode, risk metrics, trend metrics, and report helpers.
- `dashboard/src/demo`: fake sample data for demo and portfolio mode.
- `dashboard/src/components`: dashboard shell, navigation, API status, jobs, scans, vulnerability list, finding drawer, risk overview, trends, reports, remediation, settings, portfolio banner, and screenshot guide.

The dashboard is local React + Vite + TypeScript tooling. It does not collect credentials and does not expose exploit, brute-force, credentialed scan, or command execution controls.

## Data Flow

```text
scan -> findings -> storage -> API -> dashboard
```

1. The CLI or API starts a safe scan job.
2. Engines emit standard findings and supporting evidence summaries.
3. Optional local intelligence and prioritisation enrich the findings.
4. Results can be saved in SQLite and written to JSON/HTML reports.
5. The API exposes jobs, saved scans, findings, reports, exports, and remediation tracking.
6. The dashboard presents the data for local triage and reporting.

## Report Flow

```text
scan -> JSON/HTML reports -> API report endpoints -> dashboard
```

Report files are written under `reports`. API report endpoints map safe report IDs to files in that directory only, reject traversal, and serve only `.json` or `.html` reports. The dashboard uses these endpoints for local viewing and download when available.

## Safety Model

- Local-only by default.
- Authorised use only.
- API binds to `127.0.0.1` unless explicitly overridden.
- No public deployment defaults.
- Credentialed Linux and Windows scans are CLI-only.
- Dashboard does not collect credentials.
- Passive Web DAST does not submit forms, authenticate, fuzz, or send attack payloads.
- Vulnerability intelligence uses local files only and does not fetch or execute exploit code.
- Remediation tracking does not patch or modify systems.
- Secrets, API keys, `.env` files, local databases, and generated sensitive reports should not be committed.
