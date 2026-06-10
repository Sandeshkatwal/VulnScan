# VulScan Architecture

For a recruiter-friendly overview, see [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md). Architecture image placeholders live under `assets/architecture/`.

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
- `scanner.bug_bounty_scope` and `scanner.api_bug_bounty`: local Program Scope loading, validation, scope decisions, API listing, and target checks. Module names are retained for backward compatibility.
- `scanner.bug_bounty_recon` and `scanner.api_bug_bounty_recon`: manually provided target import, scope-aware safe HTTP/HTTPS metadata probing, Recon Intelligence report listing, and recon result retrieval. Module names are retained for backward compatibility.
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
- Recon Intelligence only accepts provided targets, applies Program Scope checks before probing when enabled, uses gentle HTTP/HTTPS GET requests, and stores metadata only.
- Vulnerability intelligence uses local files only and does not fetch or execute exploit code.
- Remediation tracking does not patch or modify systems.
- Secrets, API keys, `.env` files, local databases, and generated sensitive reports should not be committed.
## Version 18.8 Duplicate Detection and Fingerprinting

Version 18.8 adds `scanner/finding_fingerprint.py` and `scanner/duplicate_detection.py`.

The fingerprinting layer builds SHA-256 hashes from stable, non-sensitive metadata: host, normalised path, sorted parameter names, issue type, OWASP category, source, CVE, service, port, and method. It intentionally excludes timestamps, report IDs, random IDs, parameter values, response bodies, and secrets.

The duplicate detection layer stores fingerprints in local SQLite tables and groups exact duplicates, likely duplicates, and related findings. API and dashboard views expose these as manual-review indicators only.

## Version 18.9 Bug Intelligence Metrics

Version 18.9 adds `scanner/bug_intelligence_metrics.py`, `scanner/api_bug_intelligence_metrics.py`, CLI commands under `metrics`, protected API routes under `/bug-intelligence/metrics/...`, and `dashboard/src/components/BugIntelligenceMetricsView.tsx`.

The metrics layer is read-only and local. It calculates Personal Performance Metrics from VulScan evidence, reports, submissions, retests, duplicate metadata, OWASP mappings, and validation-derived records. It does not fetch external platform data, scrape dashboards, request credentials, store platform API tokens, or submit reports.

## Version 19.0 Release Hardening

Version 19.0 adds preferred professional command and API aliases while retaining compatibility:

- CLI: `scope list`, `scope check`, and `--scope-file`.
- Data: preferred sample directories under `data/programs`, `data/recon`, `data/endpoints`, and `data/validation`.
- API: `/program-scope/...`, `/recon`, `/endpoints/...`, and `/safe-validation`.

Legacy `/bug-bounty/...` routes and `data/bug_bounty` files remain supported as aliases. The API remains localhost-first and protected endpoints use API key enforcement when configured.
## OWASP Assessment Engine

- `scanner.owasp_rules` loads local OWASP Top 10:2025 assessment rules from `data/owasp/owasp_top10_2025_rules.json`.
- `scanner.owasp_evidence` classifies existing findings, endpoint candidates, parameter candidates, safe validation results, vulnerability intelligence, and manual records into OWASP Evidence.
- `scanner.owasp_assessment` builds OWASP Category Results, OWASP Coverage gaps, and an assessment quality score.
- CLI commands opt in with `--owasp-assess`. JSON and HTML reports include `owasp_assessment_summary`, `owasp_category_results`, `owasp_evidence_items`, and `owasp_coverage_gaps`.
- FastAPI exposes `GET /owasp/assessment/rules` and `POST /owasp/assessment/build`.

## Version 20.2 A04 Cryptographic Failures

- `scanner.owasp_a04_crypto` loads `data/owasp/a04/a04_rules.json` and builds `a04_crypto_summary`, `a04_crypto_evidence`, grouped findings, and optional TLS metadata.
- `scanner.tls_metadata` collects certificate metadata with a normal TLS handshake only.
- `--a04-checks` runs safe A04 checks from available URL, header, cookie, form, endpoint, validation, mixed content, and TLS metadata evidence.
- A04 evidence feeds `scanner.owasp_evidence` as `A04:2025` OWASP evidence when `--owasp-assess` is used.
- JSON and HTML reports include A04 summary, evidence, TLS metadata, recommendations, and limitations.
- FastAPI exposes `GET /owasp/a04/rules` and `POST /owasp/a04/assess`.

## Version 20.3 A07 Authentication Failures

- `scanner.owasp_a07_authentication` loads `data/owasp/a07/a07_rules.json` and builds `a07_authentication_summary`, `a07_authentication_evidence`, and grouped findings.
- `--a07-checks` runs safe A07 checks from available URL, header, cookie, form, endpoint, parameter, and validation metadata.
- A07 evidence feeds `scanner.owasp_evidence` as `A07:2025` OWASP evidence when `--owasp-assess` is used.
- JSON and HTML reports include A07 summary, authentication endpoints, session cookie evidence, auth form indicators, password reset indicators, rate-limit header indicators, recommendations, and limitations.
- FastAPI exposes `GET /owasp/a07/rules` and `POST /owasp/a07/assess`.
- The module does not submit forms, perform login attempts, create accounts, reset passwords, or perform repeated rate-limit testing.

## Version 20.4 A10 Mishandling of Exceptional Conditions

- `scanner.owasp_a10_error_handling` loads `data/owasp/a10/a10_rules.json` and builds `a10_error_handling_summary`, `a10_error_handling_evidence`, and grouped findings.
- `--a10-checks` analyses already observed response snippets, status codes, endpoint metadata, and validation metadata for safe A10 error-handling indicators.
- A10 evidence feeds `scanner.owasp_evidence` as `A10:2025` OWASP evidence when `--owasp-assess` is used.
- JSON and HTML reports include A10 summary, verbose error evidence, framework debug indicators, database error indicators, status code pattern analysis, fail-safe review guidance, redaction notes, recommendations, and limitations.
- FastAPI exposes `GET /owasp/a10/rules` and `POST /owasp/a10/assess`.
- The module does not force application errors, send payloads, submit forms, perform crash testing, or perform DoS testing.
### OWASP A05 Injection Candidate Analysis

- `scanner.owasp_a05_injection` loads `data/owasp/a05/a05_rules.json` and builds `a05_injection_summary`, `a05_injection_evidence`, and grouped findings.
- `scanner.reflection_analysis` performs optional harmless marker reflection observation for selected GET parameters only.
- `--a05-checks` classifies injection candidates from available endpoint, parameter, API, and form evidence. `--safe-reflection` enables limited marker reflection observation.
- A05 evidence feeds `scanner.owasp_evidence` as `A05:2025` OWASP evidence when `--owasp-assess` is used.
- FastAPI exposes `GET /owasp/a05/rules` and `POST /owasp/a05/assess`.
- The module does not submit forms, send exploit payloads, modify state, probe SSRF, perform schema fuzzing, or confirm exploitability.
## Version 20.6 A01 Candidate Engine

`scanner/owasp_a01_access_control.py` orchestrates A01 Broken Access Control candidate assessment. `scanner/access_control_candidates.py` contains passive classifiers for object identifiers, function surfaces, tenant boundaries, sensitive resources, role/permission indicators, and API access-control candidates.

The A01 module attaches `a01_access_control_summary`, `a01_access_control_evidence`, grouped informational findings, duplicate fingerprints, manual validation plans, and evidence templates. `scanner/owasp_evidence.py` maps A01 candidate evidence into the OWASP Assessment Engine for `A01:2025`.
## Version 20.7 A03 Module

The A03 Software Supply Chain module has three layers:

- `scanner/component_exposure.py` classifies JavaScript library hints, component/version exposure, dependency metadata exposure, source maps, build artifacts, and third-party script indicators from existing metadata.
- `scanner/sbom_import.py` parses local CycloneDX/SPDX JSON SBOM files and normalises component metadata without storing raw hashes.
- `scanner/owasp_a03_supply_chain.py` orchestrates evidence, summary, grouped findings, local CVE/CPE enrichment, OWASP Assessment integration, and report payloads.

The module is deliberately offline for package intelligence in Version 20.7. It accepts observed metadata and local files only.
## Version 20.8 A08 Integrity Indicator Engine

The A08 Software or Data Integrity Failures engine is a passive OWASP assessment module. `scanner/integrity_indicators.py` classifies workflow and trusted-data boundary indicators, `scanner/sri_analysis.py` analyses supplied script/stylesheet metadata for Subresource Integrity evidence, and `scanner/owasp_a08_integrity.py` orchestrates summaries, grouped findings, manual validation plans, report templates, and OWASP assessment integration.

The engine does not submit forms, upload files, trigger callbacks/webhooks, call update endpoints, fetch external resources, or execute payloads.
## Version 21.0 Authenticated Web Assessment Foundation

VulScan 21.0 adds redacted Session Profiles, Authentication Context summaries, Authenticated Scope boundary checks, Auth-Required Endpoint classification, and Role/Permission Notes. The foundation is local-only and report-safe: raw auth material is not included in JSON, HTML, dashboard, API, or terminal output.

VulScan 21.1 adds `scanner.authenticated_crawler`, `scanner.session_boundary`, and `scanner.authenticated_evidence` for GET-only Authenticated Crawl, Auth Boundary Enforcement, Session Expiry Indicator classification, and Redacted Authenticated Evidence.
## Version 21.2 Role and Permission Mapping Components

Role and Permission Mapping is implemented as pure local planning modules: `scanner/role_profiles.py`, `scanner/permission_matrix.py`, `scanner/access_control_matrix.py`, and `scanner/role_mapping_assistant.py`. API wrappers live in `scanner/api_role_mapping.py`. The modules consume existing endpoint/session metadata and generate Access-Control Matrix rows and Manual Validation Required plans without making network requests.
## Version 21.3 Access Control Manual Test Planner Components

Access Control Manual Test Planner logic lives in `scanner/access_control_test_planner.py`, `scanner/a01_manual_tests.py`, `scanner/access_control_evidence_checklist.py`, and `scanner/access_control_retest.py`. API wrappers live in `scanner/api_access_control_planner.py`. The modules create local workflow records and do not make network requests.
