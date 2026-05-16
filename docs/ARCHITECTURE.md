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
- Optional authenticated SSH audit for authorised Linux systems using one login attempt, read-only inspection commands, Linux family detection, read-only package update checks, and Linux configuration audit templates.
- Credentialed SSH audit summary output in terminal, JSON, and HTML reports without storing passwords, key values, or private key paths.
- Credentialed SSH audit profiles for `basic`, `standard`, and `detailed` read-only check depth.
- Structured SSH audit status and error-code handling for authentication, timeout, unsupported target, and command-failure paths.
- Concise, redacted credentialed audit evidence summaries with optional report-only evidence details.
- Standard finding model with sequential IDs, severity, confidence, evidence, impact, recommendation, verification, limitation, source, and timestamps.
- Prioritisation Engine risk scoring with heuristic risk score, risk label, and fix priority.
- Local SQLite scan history in `data\vulscan.db` for scans, open ports, and findings.
- Scan diffing between the latest two saved scans for a target, including new, fixed, unchanged, and changed-risk finding categories.
- Remediation status tracking for saved findings, including owner, note, first seen, last seen, and status counts.
- Storage / Assets inventory for saved targets and detected services, implemented in Version 10.4.
- CSV and JSON export of saved assets, scan history, findings, and remediation records, implemented in Version 10.5.

## Planned Later

- Host discovery for authorised internal ranges.
- Windows SMB/WinRM configuration checks.
- Broader configuration auditing.
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

Version 10.4 adds asset inventory in SQLite. Saved scans create or update asset records, track first seen and last seen timestamps, count scans, record latest open-port and finding counts, and maintain a service inventory for exposed TCP services. This marks Storage / Assets as implemented and provides the foundation for future dashboard asset pages, exposure management, asset criticality, and API inventory endpoints.

Version 10.5 adds CSV and JSON exports from the local SQLite database. CSV supports Excel and spreadsheet workflows, while JSON supports future APIs, dashboards, integrations, and backup workflows. Export files are written to `exports`, which is ignored by Git.

Version 11.0 adds authenticated SSH auditing for authorised Linux systems. The SSH audit uses Paramiko, requires explicit credentials, attempts only one login, and never stores SSH passwords or private key paths in reports, the database, logs, or terminal output. After authentication it runs read-only commands only, including OS inspection, effective `sshd -T` configuration where available, host firewall status where available, package-manager discovery, and package update checks. Findings are emitted through the standard finding model, then flow through risk scoring, terminal output, JSON and HTML reports, SQLite history, scan diffing, remediation tracking, asset inventory, and exports.

Version 11.1 improves Linux package and patch checks. VulScan detects OS family from `/etc/os-release`, checks supported package managers with `command -v`, and runs only read-only package update checks for `apt`, `dnf`, `yum`, `pacman`, and `zypper`. It records structured SSH audit fields for OS family, selected package manager, package update count, package update sample, and package check status. The package findings are for patch management review and do not replace CVE intelligence, vendor advisories, exploitability analysis, or asset criticality.

Version 11.3 adds Linux configuration audit templates over the existing authenticated SSH session. The checks are read-only and cover host firewall indicators, logging service indicators, password policy indicators, temporary directory sticky-bit indicators, cleartext service exposure indicators, and a basic Linux configuration audit completion summary. Findings use the `linux_config_audit` source and flow through the existing risk scoring, reporting, SQLite, diff, remediation, asset, and export pipeline. These checks are indicators and are not a full CIS benchmark implementation yet.

Version 11.4 refines SSH audit reporting. Scan results now include a sanitized `ssh_audit_summary` with authentication status, username, auth method, OS family, hostname, kernel summary, package indicators, SSH hardening status, Linux configuration status, total SSH findings, highest SSH risk, and limitations. Terminal findings are grouped by source, and JSON/HTML reports expose the SSH summary while keeping SSH findings in the standard top-level finding pipeline.

Version 11.5 adds credentialed audit profiles for authenticated SSH audits. The default `standard` profile runs login verification, OS and SSH hardening checks, package and patch indicators, firewall indicators, and logging indicators. The `basic` profile limits the run to fast credentialed verification and SSH hardening review. The `detailed` profile adds password policy indicators, temporary directory sticky-bit checks, and cleartext service exposure indicators. Profile metadata is included in `ssh_audit_summary` as the selected profile, description, enabled checks, and skipped checks.

Version 11.6 adds SSH audit test fixtures and structured error handling. SSH audit results use `success`, `failed`, `skipped`, and `partial` status values with safe error codes and user-facing messages. Remote command execution is wrapped so timeouts and command failures return structured metadata rather than crashing the scan. Unit tests use fake fixture files and mocked SSH behavior, so parser and error-path tests do not require a live SSH server or real credentials.

Version 11.7 improves credentialed audit evidence quality. SSH, package, and Linux configuration findings keep the backward-compatible short `evidence` string while adding optional `evidence_details` for JSON and HTML reports. Evidence helpers redact obvious secrets, avoid full raw SSH output by default, limit long text and package samples, and keep CSV/database evidence concise for remediation workflows.

Version 11.8 adds credentialed audit performance and timeout controls. SSH audits now accept separate connection, command, and overall audit timeouts, with profile defaults of 30 seconds for `basic`, 60 seconds for `standard`, and 90 seconds for `detailed`. Remote command execution records per-command duration, timeout status, and safe error codes. Overall audit budget exhaustion skips remaining checks, records `SSH_AUDIT_TIME_BUDGET_EXCEEDED`, and returns partial results through the existing report pipeline rather than aborting the whole scan. The sanitized `ssh_audit_summary` includes timeout settings, total duration, planned/completed/failed/skipped checks, timed-out command count, slowest command metadata, status, error code, and performance notes.

Version 11.9 adds a normalised credentialed audit result layer. `scanner.credentialed_result` defines lightweight standard-library dataclasses for `CredentialedAuditResult`, `CredentialedCheckResult`, and safe credentialed audit errors. Existing SSH output is converted into this model and exposed as top-level `credentialed_audits` while preserving `ssh_audit`, `ssh_audit_summary`, `open_ports`, `findings`, and report summaries. JSON and HTML reports include the normalised module summary, and the standard findings pipeline still drives database history, diffing, remediation, asset inventory, and exports. The model intentionally includes username and auth method but excludes passwords, private key contents, and private key paths so future Windows SMB/WinRM modules can plug into the same reporting flow safely.

Version 12.1 extends the Windows SMB/WinRM audit foundation with a safe WinRM authentication validation. `scanner.windows_audit` still performs socket connection checks against SMB 445, NetBIOS/SMB 139, WinRM HTTP 5985, WinRM HTTPS 5986, and RDP 3389. When `--windows-auth-method winrm` is selected, it requires explicitly provided credentials, selects HTTPS 5986 before HTTP 5985 based on reachability, uses `pywinrm` when available, and performs one harmless command such as `hostname` to validate authentication. Missing `pywinrm`, unreachable WinRM, authentication failure, timeouts, and connection errors are normalised into safe error codes without secrets.

Windows audit emits standard findings with source `windows_audit`, a top-level `windows_audit_summary`, and a normalised `credentialed_audits` entry with source `windows_audit`. The database, diffing, remediation, asset inventory, and exports continue to use the existing findings pipeline, so no Windows-specific tables are introduced. Version 12.1 does not enumerate SMB shares, query the registry, enumerate patches, list users, list processes, list files, exploit, brute force, dump credentials, modify systems, or restart services; deeper authenticated Windows policy and patch checks are planned for later versions.

The scanner still preserves `open_ports` separately because open ports are useful as asset inventory even when they do not represent confirmed vulnerabilities.
