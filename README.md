# VulScan

Local authorised security assessment, vulnerability management, and bug intelligence platform.

![Python 3.11](https://img.shields.io/badge/Python-3.11-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-local%20API-green)
![React](https://img.shields.io/badge/React-dashboard-61dafb)
![TypeScript](https://img.shields.io/badge/TypeScript-dashboard-3178c6)
![SQLite](https://img.shields.io/badge/SQLite-persistence-lightgrey)
![Security Tooling](https://img.shields.io/badge/Security%20Tooling-authorised%20use-red)
![Local First](https://img.shields.io/badge/Local%20First-no%20cloud%20required-informational)
![Authorised Testing Only](https://img.shields.io/badge/Authorised%20Testing-Only-critical)

## Safety Notice

VulScan is designed for systems you own or have explicit permission to test. It is not intended for unauthorised scanning, exploitation, brute force, credential attacks, or destructive testing.

## Project Overview

VulScan is a local platform for authorised security assessment and vulnerability management. It combines discovery, credentialed audit foundations, passive web assessment, local vulnerability intelligence, prioritisation, reporting, remediation tracking, and dashboard visualisation.

The project exists to show how scanner output can become a practical security workflow instead of a raw list of findings. It stores results locally, enriches findings with risk and prioritisation context, produces JSON/HTML reports, exposes a local FastAPI API, and presents the workflow in a React dashboard.

VulScan is intended for security learners, junior security engineers, portfolio reviewers, and authorised internal testing labs. The Bug Intelligence Engine supports responsible disclosure, bug bounty workflow compatibility, and internal security testing through Program Scope, Recon Intelligence, Endpoint Intelligence, OWASP Indicator Mapping, Safe Validation, Evidence Capture, Security Finding Reports, Submission and Retest Tracker, Duplicate Detection, and Performance Metrics.

## Key Features

| Area | Capability | Status |
|---|---|---|
| Discovery Engine | Safe TCP connect scanning and service identification | Working |
| Credentialed Linux Audit | SSH-based read-only Linux audit checks | Working |
| Windows Audit | Safe Windows reachability and optional read-only WinRM indicators | Working |
| Passive Web DAST | Bounded crawl, headers, cookies, forms, robots, sitemap, and scope-aware reporting | Working |
| Vulnerability Intelligence | Local rules and local advisory-style matching | Working |
| CVSS/EPSS/Exploit Metadata | Local prioritisation signals only, no exploit download or execution | Working |
| Prioritisation Engine | Risk scoring, asset context, and fix-first guidance | Working |
| Fix-First Dashboard | Prioritised remediation dashboard data | Working |
| Trend Tracking | Latest scan comparison and trend context | Working |
| API | Local FastAPI API with jobs, reports, filtering, persistence, and remediation | Working |
| React Dashboard | Local dashboard for jobs, findings, risk, trends, reports, remediation, and Bug Intelligence | Working |
| Program Scope | Local scope files, in-scope/out-of-scope decisions, compatibility aliases | Working |
| Recon Intelligence | Scope-aware metadata-only recon for provided targets | Working |
| Endpoint Intelligence | URL/path analysis and endpoint candidate discovery | Working |
| OWASP Mapping | Indicator-only OWASP Top 10 mapping | Working |
| OWASP Assessment Engine | OWASP Top 10:2025 evidence, category results, confidence, coverage gaps, and manual validation workflow | Foundation |
| Safe Validation | Limited non-destructive validation checks | Working |
| Evidence Capture | Redacted, report-safe evidence summaries | Working |
| Security Finding Reports | Local report listing and evidence/report workflow | Working |
| Submission and Retest Tracker | Local status, follow-up, retest, and payment tracking | Working |
| Duplicate Detection | Metadata-only Finding Fingerprinting and duplicate groups | Working |
| Performance Metrics | Local Bug Intelligence progress, quality, outcome, and programme metrics | Working |

## Architecture

```text
VulScan
├── Discovery Engine
├── Credentialed Scan Engine
├── Web DAST Engine
├── Vulnerability Intelligence Engine
├── Prioritisation Engine
├── Bug Intelligence Engine
├── Storage
├── API
└── Dashboard
```

![Architecture Diagram](assets/architecture/vulscan-architecture.png)

Architecture diagram placeholder. Add screenshot/image before final portfolio release.

## Dashboard Preview

![Dashboard Overview](assets/screenshots/dashboard-overview.png)
![Jobs](assets/screenshots/dashboard-jobs.png)
![Vulnerabilities](assets/screenshots/dashboard-vulnerabilities.png)
![Risk](assets/screenshots/dashboard-risk.png)
![Reports](assets/screenshots/dashboard-reports.png)
![Bug Intelligence Workflow](assets/screenshots/bug-intelligence-workflow.png)
![Performance Metrics](assets/screenshots/performance-metrics.png)

Screenshot placeholders. Use demo mode and add final images before public portfolio release.

## Quick Start

Backend:

```powershell
python -m venv .venv311
.\.venv311\Scripts\python.exe -m pip install -r requirements.txt
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main api
```

Dashboard:

```powershell
cd dashboard
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

## Demo Mode

Dashboard demo mode uses fake sample data only. It is intended for screenshots, UI review, and portfolio presentation.

Example dashboard environment values:

```text
VITE_VULSCAN_DEMO_MODE=true
VITE_VULSCAN_PORTFOLIO_MODE=true
VITE_VULSCAN_SCREENSHOT_MODE=true
```

Do not commit `.env` files or secrets.

## Example Commands

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --headers --cookies --forms --passive-summary
.\.venv311\Scripts\python.exe -m scanner.main recon --targets-file data\recon\sample_targets.txt --scope-file data\programs\sample_program_scope.json --enforce-scope
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --scope-file data\programs\sample_program_scope.json --enforce-scope
.\.venv311\Scripts\python.exe -m scanner.main validate --targets-file data\validation\sample_validation_targets.json --scope-file data\programs\sample_program_scope.json --enforce-scope
.\.venv311\Scripts\python.exe -m scanner.main evidence list
.\.venv311\Scripts\python.exe -m scanner.main security-report list
.\.venv311\Scripts\python.exe -m scanner.main submission list
.\.venv311\Scripts\python.exe -m scanner.main metrics summary
.\.venv311\Scripts\python.exe -m scanner.main api
cd dashboard
npm run dev
```

## Bug Intelligence Workflow

```text
Program Scope -> Recon -> Endpoints -> OWASP Mapping -> Safe Validation -> Evidence -> Security Report -> Submission -> Retest -> Metrics
```

This workflow supports responsible disclosure, bug bounty workflow compatibility, and internal security testing. It is local and tracking-oriented: VulScan does not submit reports to external platforms, store platform tokens, scrape dashboards, or execute exploit payloads.

## Reports and Evidence

VulScan produces local JSON and HTML reports for scanner output and workflow modules. Evidence Capture stores concise, redacted summaries designed for review and reporting. Security Finding Reports organise evidence, impact, reproduction notes, remediation guidance, and submission tracking context.

Report access through the local API is restricted to files under the local `reports` directory and blocks path traversal. Sensitive values such as passwords, tokens, cookies, private keys, and authorisation headers are redacted where evidence/report helpers process text.

## Limitations

- VulScan is not a replacement for Nessus, Qualys, Burp Suite, or a full enterprise vulnerability management platform.
- It is not an exploitation framework.
- Local/offline vulnerability intelligence can become stale.
- Findings and indicators require manual validation.
- Demo mode uses fake data only.
- VulScan does not submit to external disclosure platforms.
- Enterprise RBAC, hardened deployment, and multi-user workflows are not implemented yet.

## Roadmap

- Docker or dev container setup.
- CI/CD workflow.
- PDF reporting.
- Stronger authentication and deployment hardening.
- Plugin system.
- SBOM support.
- Optional safe active check expansion.
- Broader test coverage and dashboard visual regression checks.

## What This Project Demonstrates

- Python security tooling and safe scanner design.
- FastAPI API design with local-first safety controls.
- React and TypeScript dashboard development.
- SQLite persistence and report workflows.
- Vulnerability management and remediation tracking.
- OWASP indicator mapping and prioritisation logic.
- Responsible disclosure workflow modelling.
- Safety-focused engineering, documentation, and release discipline.

## Documentation

- [Installation](docs/INSTALLATION.md)
- [Usage](docs/USAGE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Safety](docs/SAFETY.md)
- [Bug Intelligence](docs/BUG_INTELLIGENCE.md)
- [Bug Intelligence Workflow](docs/BUG_INTELLIGENCE_WORKFLOW.md)
- [Command Reference](docs/COMMAND_REFERENCE.md)
- [Portfolio Guide](docs/PORTFOLIO_GUIDE.md)
- [Screenshot Checklist](docs/SCREENSHOT_CHECKLIST.md)
- [Interview Talking Points](docs/INTERVIEW_TALKING_POINTS.md)
- [Limitations](docs/LIMITATIONS.md)
- [Future Roadmap](docs/FUTURE_ROADMAP.md)
- [Project Summary](docs/PROJECT_SUMMARY.md)
- [Dashboard](dashboard/README.md)

## License

License not selected yet. Add a `LICENSE` file before public release.
## OWASP Assessment Engine

Version 20.0 adds an OWASP Top 10:2025 assessment foundation for category-level evidence, confidence, coverage gaps, and manual validation workflow.

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --owasp-assess --json --html
```

The OWASP assessment score measures coverage and evidence quality. It is not a security rating, and no indicator found does not mean the category is secure.
# Version 20.2 A04 Cryptographic Failures

VulScan includes safe OWASP A04 Cryptographic Failures checks for authorised web assessments:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --a04-checks --owasp-assess --json --html
```

The module reports transport security indicators, cookie security evidence, sensitive data over cleartext indicators, HSTS evidence, mixed content indicators, and TLS metadata. It does not submit forms, capture credentials, store cookie values, store secrets, test weak TLS ciphers, or perform downgrade testing.

# Version 20.3 A07 Authentication Failures

VulScan includes safe OWASP A07 Authentication Failures checks for authorised web assessments:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --a07-checks --owasp-assess --json --html
```

The module reports authentication indicators, session management indicators, login workflow evidence, password reset workflow evidence, cookie/session evidence, rate-limit header indicators, and manual validation needs. It does not perform login attempts, brute force, credential stuffing, password guessing, MFA bypass testing, account creation, password reset, or form submission.

# Version 20.4 A10 Mishandling of Exceptional Conditions

VulScan includes safe OWASP A10 Mishandling of Exceptional Conditions checks for authorised web assessments:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --a10-checks --owasp-assess --json --html
```

The module reports error-handling indicators, exception exposure evidence, verbose error evidence, framework debug indicators, status code patterns, sensitive error content, fail-safe review required notes, and manual validation required status. It analyses already observed evidence only and does not force errors, send payloads, submit forms, modify server-side state, perform crash testing, or perform DoS testing.
### OWASP A05 Injection Candidate Analysis

```powershell
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --a05-checks --owasp-assess --json --html
```

Optional safe reflection:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --a05-checks --safe-reflection --max-reflection-checks 10 --owasp-assess --json --html
```

The module reports A05 Injection candidates, input handling indicators, parameter intelligence, form input candidates, API input candidates, and optional harmless marker reflection observations. It does not use exploit payloads, submit forms, modify state, or confirm exploitability. Manual validation is required.
## Version 20.6 A01 Broken Access Control

Version 20.6 adds an A01 Broken Access Control Candidate Engine for safe, authorised OWASP-focused assessment. It identifies access-control candidates from endpoints, parameters, URL structures, object identifiers, admin/function surfaces, tenant indicators, export/download workflows, APIs, and evidence records, then generates candidate evidence, confidence scoring, manual validation plans, and report-ready templates.

The A01 engine is candidate-only: no auth bypass automation, no cross-account testing, no credential attacks, no privilege escalation attempts, and no state-changing requests. See `docs/OWASP_A01_BROKEN_ACCESS_CONTROL.md`.
