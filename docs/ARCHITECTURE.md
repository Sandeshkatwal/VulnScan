# VulScan Architecture

VulScan is an authorised-use defensive vulnerability scanning and auditing tool. The current implementation is intentionally safe, limited, and TCP-connect based.

## Long-Term Architecture

```text
Vulnerability Scanner
├── Discovery Engine
│   ├── Host discovery
│   ├── Port scanning
│   └── Service detection
├── Credentialed Scan Engine
│   ├── SSH scanner
│   ├── SMB/Windows scanner
│   └── Package/configuration checks
├── Web DAST Engine
│   ├── Crawler
│   ├── Header checker
│   ├── Injection tester
│   └── Cookie checker
├── Vulnerability Intelligence Engine
│   ├── CVE database
│   ├── CVSS score
│   ├── EPSS score
│   └── Exploit availability
├── Prioritisation Engine
│   ├── Risk scoring
│   ├── Asset criticality
│   └── Fix-first ranking
├── Storage
│   ├── Assets
│   ├── Findings
│   ├── Scan history
│   └── Reports
├── API
│   ├── Start scan
│   ├── Get results
│   └── Export data
└── Dashboard
    ├── Risk overview
    ├── Vulnerability list
    ├── Trends
    └── Reports
```

## Implemented Now

- TCP connect port scanning against a fixed common-port list.
- Passive service detection from common TCP port mappings.
- Service-specific defensive recommendations.
- JSON and HTML report output.
- Optional HTTP security header audit using one normal GET request to `/`.
- Optional passive TLS certificate audit for detected HTTPS services.
- Standard finding model with sequential IDs, severity, confidence, evidence, impact, recommendation, verification, limitation, source, and timestamps.
- Prioritisation Engine risk scoring with heuristic risk score, risk label, and fix priority.
- Local SQLite scan history in `data\vulscan.db` for scans, open ports, and findings.
- Scan diffing between the latest two saved scans for a target, including new, fixed, unchanged, and changed-risk finding categories.
- Remediation status tracking for saved findings, including owner, note, first seen, last seen, and status counts.

## Planned Later

- Host discovery for authorised internal ranges.
- Credentialed SSH and Windows/SMB configuration checks.
- Package and configuration auditing.
- Web DAST features only when explicitly designed with strict safety controls.
- CVE, CVSS, EPSS, and exploit-availability enrichment.
- Asset criticality, API access, dashboard views, richer fix-first ranking, and expanded remediation workflow tracking.

## How Version 8 and 9 Help

Version 8 adds a standard `Finding` model and top-level report `findings` section. Version 9 adds heuristic risk scoring and fix priority. Together, they give future engines a shared output contract, so port exposure, HTTP checks, TLS checks, credentialed checks, CVE enrichment, and prioritisation can all write comparable records.

Sequential finding IDs make reports easier to reference during remediation. Structured fields such as `severity`, `confidence`, `impact`, `source`, `risk_score`, `risk_label`, `fix_priority`, and `created_at` provide the data needed for scan history storage, API responses, dashboard filtering, and richer prioritisation.

Version 10 adds local SQLite storage. Saving scan summaries, open ports, and findings in `data\vulscan.db` creates the foundation for future diffing between scans, remediation status tracking, trend charts, and dashboard history views.

Version 10.1 improves history validation and summaries. The CLI can limit returned history rows, clearly report missing databases, missing required tables, or missing target history, and summarize latest-scan severity and risk-label counts without changing the database schema.

Version 10.2 adds scan diffing without changing the database schema. It compares findings from the latest two saved scans for the same target using stable fingerprints, reports new and fixed findings, highlights risk or severity changes, and calculates whether the total risk score is improving, worsening, or unchanged. This supports future remediation tracking, trend reporting, dashboard change views, and API endpoints for scan comparison.

Version 10.3 adds remediation status tracking in SQLite. Findings are matched using the same stable fingerprint model as scan diffing, so status can persist across scan runs even when sequential finding IDs change. This supports future dashboard remediation queues, API update endpoints, reporting filters, remediation SLAs, and fix verification workflows.

The scanner still preserves `open_ports` separately because open ports are useful as asset inventory even when they do not represent confirmed vulnerabilities.
