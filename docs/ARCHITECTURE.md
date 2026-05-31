# VulScan Architecture

## Version 18.2 Endpoint Discovery

Endpoint discovery is implemented as a local, no-network analysis pipeline:

- `scanner.endpoint_discovery` loads supplied URL/path lists, normalises and
  deduplicates URLs, applies optional program scope decisions, classifies
  endpoints, scores candidates, and builds report-ready results.
- `scanner.parameter_intelligence` classifies parameter names into manual
  validation categories and redacts sensitive parameter values.
- `scanner.api_app` exposes `POST /bug-bounty/endpoints/analyse` and
  `GET /bug-bounty/endpoints/reports` behind the same API key dependency as
  other protected Bug Intelligence routes.
- Reports include `endpoint_discovery`, `endpoint_results`,
  `parameter_results`, `endpoint_skipped`, and sparse candidate findings.
- The React dashboard adds an Endpoint Discovery view under Bug Intelligence.

The component does not crawl, fuzz, submit forms, send payloads, execute
exploits, or confirm vulnerabilities.

## Version 18.3 OWASP Mapping

OWASP Top 10 mapping is a report enrichment layer:

- `scanner.owasp_mapping` loads local category data from
  `data/owasp/owasp_top10_2025_mapping.json`.
- Findings, endpoint candidates, and parameter candidates are mapped to at most
  three OWASP Top 10:2025 indicator categories.
- `attach_owasp_metadata` adds `owasp_top10_summary`,
  `owasp_top10_mapped_items`, and finding-level `owasp_categories`.
- CLI commands opt in with `--owasp-map`.
- FastAPI exposes `GET /owasp/categories` and `POST /owasp/map`.
- Reports and dashboard render indicator counts, mapped items, confidence, and
  coverage gaps.

The layer does not perform active security testing and does not confirm OWASP
vulnerabilities.

## Version 18.4 Safe Active Validation

Safe active validation is a small, opt-in, non-destructive request layer:

- `scanner.safe_active_validation` loads target JSON files, enforces optional
  program scope before requests, applies low-rate request controls, and runs
  only explicitly supported safe checks.
- Supported checks are reflected marker observation, same-origin redirect
  behaviour, CORS header observation, directory listing indicators, known
  public default files, and `OPTIONS` method observation.
- The module stores evidence summaries only. It does not store response bodies,
  cookies, tokens, passwords, or private keys.
- `POST /bug-bounty/validate` exposes the same checks through the local API.
- Reports include `safe_active_validation`,
  `safe_active_validation_results`, and `safe_active_validation_skipped`.
- The dashboard provides a Safe Validation view with safety wording, scope
  controls, allowed check selection, result tables, and evidence summaries.

The module does not run exploitation, SQL injection testing, XSS payloads, SSRF
testing, file upload exploitation, authentication bypass, brute force, form
submission, payment testing, or destructive HTTP methods.

VulScan is a local authorised vulnerability scanning and vulnerability management platform. The architecture separates evidence collection, enrichment, prioritisation, storage, API access, and dashboard presentation.

## High-Level Architecture

```text
VulScan
├── Discovery Engine
├── Credentialed Scan Engine
├── Web DAST Engine
├── Program Scope Manager
├── Recon Intelligence Foundation
├── Endpoint Intelligence
├── Safe Active Validation
├── Submission and Retest Tracker
├── Bug Intelligence Workflow Dashboard
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
- `scanner.bug_bounty_scope` and `scanner.api_bug_bounty`: local program scope loading, validation, scope decisions, API listing, and target checks. Module names are retained for backward compatibility.
- `scanner.bug_bounty_recon` and `scanner.api_bug_bounty_recon`: manually provided target import, scope-aware safe HTTP/HTTPS metadata probing, recon report listing, and recon result retrieval.
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
- `dashboard/src/components`: dashboard shell, navigation, API status, jobs, scans, vulnerability list, finding drawer, risk overview, trends, Evidence & Reports, remediation, Program Scope, Recon Intelligence, endpoints, Safe Validation, Submission Tracker, settings, portfolio banner, and screenshot guide.

## Version 18.6 Submission and Retest Tracking

- `scanner.submission_tracker` stores local Security Finding Report submission records, retest records, and timeline events in SQLite.
- `scanner.api_submission_tracker` exposes tracking helpers through protected API routes.
- API routes under `/submissions` and `/retests` are tracking-only. They do not submit reports externally, accept platform credentials, or run retest activity.
- The dashboard Submission Tracker view provides summary cards, submission creation, status updates, timeline events, and retest checklist tracking.

## Version 18.7 Bug Intelligence Workflow Dashboard

- `dashboard/src/components/BugIntelligenceWorkflow.tsx` aggregates existing local API data into a workflow overview.
- `dashboard/src/utils/workflowMetrics.ts` derives step status, readiness score, next best actions, and a timeline on the client side.
- The workflow is Scope -> Recon -> Endpoints -> OWASP -> Validation -> Evidence -> Report -> Submission -> Retest.
- No new active testing or external submission is performed by the dashboard overview.

The dashboard is local React + Vite + TypeScript tooling. It does not collect credentials and does not expose exploit, brute-force, credentialed scan, or command execution controls.

## Data Flow

```text
scan -> findings -> storage -> API -> dashboard
manual recon targets -> scope validation -> safe HTTP metadata -> JSON/HTML recon reports -> dashboard
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

Recon reports are written under `reports/recon` when requested. They include summary counts, live asset metadata, skipped target decisions, passive technology hints, and limitations. They do not include response bodies, cookies, tokens, passwords, or private keys.

## Safety Model

- Local-only by default.
- Authorised use only.
- API binds to `127.0.0.1` unless explicitly overridden.
- No public deployment defaults.
- Credentialed Linux and Windows scans are CLI-only.
- Dashboard does not collect credentials.
- Passive Web DAST does not submit forms, authenticate, fuzz, or send attack payloads.
- Bug bounty scope decisions are local decision support and do not replace live program policy verification.
- Bug bounty recon only accepts provided targets, applies scope checks before probing, uses gentle HTTP/HTTPS GET requests, and stores metadata only.
- Vulnerability intelligence uses local files only and does not fetch or execute exploit code.
- Remediation tracking does not patch or modify systems.
- Secrets, API keys, `.env` files, local databases, and generated sensitive reports should not be committed.
## Version 18.8 Duplicate Detection and Fingerprinting

Version 18.8 adds `scanner/finding_fingerprint.py` and `scanner/duplicate_detection.py`.

The fingerprinting layer builds SHA-256 hashes from stable, non-sensitive metadata: host, normalised path, sorted parameter names, issue type, OWASP category, source, CVE, service, port, and method. It intentionally excludes timestamps, report IDs, random IDs, parameter values, response bodies, and secrets.

The duplicate detection layer stores fingerprints in local SQLite tables and groups exact duplicates, likely duplicates, and related findings. API and dashboard views expose these as manual-review indicators only.
