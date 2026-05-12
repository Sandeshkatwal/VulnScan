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

## Planned Later

- Host discovery for authorised internal ranges.
- Credentialed SSH and Windows/SMB configuration checks.
- Package and configuration auditing.
- Web DAST features only when explicitly designed with strict safety controls.
- CVE, CVSS, EPSS, and exploit-availability enrichment.
- Risk scoring, asset criticality, scan history, API access, and dashboard views.

## How Version 8 Helps

Version 8 adds a standard `Finding` model and top-level report `findings` section. That gives future engines a shared output contract, so port exposure, HTTP checks, TLS checks, credentialed checks, CVE enrichment, and prioritisation can all write comparable records.

Sequential finding IDs make reports easier to reference during remediation. Structured fields such as `severity`, `confidence`, `impact`, `source`, and `created_at` provide the data needed for future risk scoring, scan history storage, API responses, and dashboard filtering.

The scanner still preserves `open_ports` separately because open ports are useful as asset inventory even when they do not represent confirmed vulnerabilities.
