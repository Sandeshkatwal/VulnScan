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
│   ├── Form discovery
│   ├── Cookie checker
│   ├── Passive risk summary
│   ├── Scope controls
│   ├── Rate limiting and politeness
│   ├── robots.txt awareness
│   └── Sitemap discovery
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
- Web DAST crawler foundation using bounded same-host GET requests only.
- Passive Web DAST security header checks for crawled pages.
- Value-free Web DAST cookie attribute audit.
- Passive Web DAST form discovery and classification.
- Consolidated passive Web DAST risk summary.
- Web DAST scope and allowlist controls.
- Web DAST rate limiting, retry limits, Retry-After handling, and max-error controls.
- Web DAST robots.txt awareness.
- Web DAST sitemap discovery.
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

Version 12.6 extends the Windows SMB/WinRM audit foundation with safe read-only Windows registry audit templates. `scanner.windows_audit` still performs socket connection checks against SMB 445, NetBIOS/SMB 139, WinRM HTTP 5985, WinRM HTTPS 5986, and RDP 3389. When `--windows-auth-method winrm` is selected, it requires explicitly provided credentials, selects HTTPS 5986 before HTTP 5985 based on reachability, uses `pywinrm` when available, and performs one harmless command such as `hostname` to validate authentication. Missing `pywinrm`, unreachable WinRM, authentication failure, timeouts, and connection errors are normalised into safe error codes without secrets.

When `--windows-host-info` is selected, host information commands run only after successful WinRM authentication. The allowed read-only command set collects hostname, current identity, PowerShell version, OS caption/version/build/architecture/boot/install dates, computer system domain/workgroup/manufacturer/model, and timezone. The parsed values are stored under `windows_audit_summary.windows_host_info` and mirrored into the normalised credentialed audit summary/metadata for future Windows patch, policy, Defender, and firewall modules.

When `--windows-security-status` is selected, Firewall and Defender commands run only after successful WinRM authentication. The allowed read-only command set collects `Get-NetFirewallProfile`, `Get-Service WinDefend`, and `Get-MpComputerStatus` fields. It does not call `Set-NetFirewallProfile`, `Set-MpPreference`, start or stop services, enable or disable firewall rules, enumerate individual firewall rules, query registry, or query local security policy. Partial status is supported when Defender cmdlets are unavailable or restricted.

When `--windows-policy-status` is selected, local security policy indicator commands run only after successful WinRM authentication. The allowed command set is limited to `net accounts`; parsing lives in `scanner.windows_policy_audit` and stores safe values under `windows_audit_summary.windows_policy_status`. It does not call `secedit /export`, `gpresult`, registry queries, local user enumeration, local group enumeration, password reset commands, account modification commands, or policy modification commands. Domain Group Policy or enterprise identity controls may override local indicators, and VulScan does not perform full Group Policy analysis.

When `--windows-registry-audit` is selected, registry checks run only after successful WinRM authentication. `scanner.windows_registry_audit` loads an explicit JSON template, validates that each enabled check uses supported operator syntax and the HKLM hive, builds exact-path read-only `Get-ItemProperty` commands, and stores safe results under `windows_audit_summary.windows_registry_audit`. It does not support HKCU, wildcard paths, recursive enumeration, broad registry trees, registry hive export, or registry writes. Missing values are reported as unknown/not present and interpreted cautiously.

Windows audit emits standard findings with source `windows_audit`, Windows security findings with source `windows_security_audit`, Windows policy findings with source `windows_policy_audit`, Windows registry findings with source `windows_registry_audit`, a top-level `windows_audit_summary`, and a normalised `credentialed_audits` entry with source `windows_audit`. The database, diffing, remediation, asset inventory, and exports continue to use the existing findings pipeline, so no Windows-specific tables are introduced. Version 12.6 does not enumerate SMB shares, query broad registry trees, export registry hives, export security policy, enumerate patches, list users, list groups, list processes, list files, collect secrets, collect browser data, collect hashes, collect tokens, collect private keys, exploit, brute force, dump credentials, modify systems, or restart services.

Version 12.8 reuses `scanner.evidence` for Windows evidence quality and redaction. Windows findings keep the backward-compatible short `evidence` string and can include `evidence_details` with source, safe command label, observed value, expected value, raw-output-included status, redaction status, and limitation. JSON, HTML, and export writers recursively redact report containers before writing. SQLite continues to store the short evidence string through the existing schema.

Version 12.9 adds Windows audit orchestration metadata without adding new intrusive checks. `scanner.windows_audit` validates connection, command, and overall audit timeout options, wraps WinRM command execution in structured result dictionaries, tracks section-level success/failed/skipped/partial status, and records performance fields such as timed-out command count and slowest command. The overall audit budget is checked before sections and commands; budget exhaustion skips remaining requested work and returns partial results through the existing findings and credentialed audit pipelines.

Version 12.10 adds `scanner.windows_result`, a lightweight standard-library normalisation layer for Windows audit sections and checks. It exposes `WindowsAuditSectionResult` and `WindowsCheckResult`, normalises safe Windows errors, and builds `windows_audit_sections` for service reachability, WinRM authentication, host information, security status, patch status, local security policy, and registry audit. `windows_audit_consolidated_summary` is now derived from these sections where possible, while the legacy `windows_audit_summary`, `credentialed_audits`, `findings`, `open_ports`, and general summary structures remain intact. The section model avoids passwords, secrets, private key paths, tokens, hashes, and raw command output by default, and prepares the Windows audit path for profiles, API responses, and dashboard views without adding intrusive checks.

Version 12.11 adds `scanner.windows_audit_profiles`, a small profile resolver for controlled Windows audit depth. Profiles are additive defaults: `foundation` enables service reachability and optional WinRM authentication, `standard` adds host information, security status, and patch status when WinRM is available, and `detailed` adds local policy and the default registry audit template. Manual flags extend the selected profile without disabling profile-selected sections. Profile metadata is copied into `windows_audit_summary`, `windows_audit_consolidated_summary`, and each normalised Windows section as `enabled_by_profile`, `enabled_by_manual_flag`, and `skipped_reason`, so future dashboards and APIs can explain why a section ran or was skipped without changing the existing findings pipeline.

Version 12.12 adds `scanner.windows_demo`, a fake-data Windows audit generator for demonstrations and report testing. The CLI uses this path only when `--windows-demo` is set. It constructs a local demo scan result and a Windows audit result without calling TCP scanning, WinRM, socket reachability, or credentialed audit code. Demo output still flows through the normal finding, risk scoring, Windows section normalisation, JSON, HTML, credentialed audit, and optional SQLite save paths, but it is marked with `demo_mode: true` and a visible demo notice. Demo reports are sample data and are not valid security assessment evidence.

Version 13.0 adds the first Web DAST Engine component in `scanner.web_crawler`. The new `web-scan` command normalises a start URL, restricts crawling to the same host by default, respects maximum page and depth limits, skips unsafe schemes and common static/binary files, and records pages, links, forms, response timing, and crawl limitations. Forms are parsed for input names, input types, password fields, and file-upload fields, but are never submitted. Findings use the existing standard finding model and flow into JSON and HTML reports alongside `web_scan_summary`, `crawled_pages`, `discovered_forms`, and `web_findings`. Version 13.0 deliberately does not fuzz, authenticate, test SQL injection, test XSS, submit forms, or crawl external domains by default. Future Web DAST work can integrate header checks, cookie audit, and safe opt-in checks on top of this bounded crawl data.

Version 13.1 adds `scanner.web_header_audit`, a passive header checker integrated into `web-scan --headers`. It consumes response header metadata already collected by the crawler, checks common browser security headers, disclosure headers, and cookie flag indicators, and deduplicates findings by issue type with affected-page counts. It adds `web_header_summary` and `web_header_results` to JSON and HTML reports. It does not send additional payloads, submit forms, authenticate, crawl external domains, or perform SQL injection or XSS testing.

Version 13.2 adds `scanner.web_cookie_audit`, a dedicated cookie attribute parser and audit layer. The crawler extracts `Set-Cookie` metadata into value-free cookie records, storing names and attributes only. Cookie values, session IDs, and tokens are not stored or printed. `web-scan --cookies` checks only the start URL unless `--crawl` is explicitly provided, while `--headers` also runs cookie auditing because cookies are part of passive header analysis. Cookie findings are deduplicated by cookie name, issue type, host, and scheme, and the report adds `web_cookie_summary` and `web_cookie_results`.

Version 13.3 adds `scanner.web_form_audit`, an enhanced form discovery layer over the crawler's parsed HTML form metadata. The crawler records form IDs, methods, action URLs, action hosts, HTTPS-to-HTTP submission indicators, input names/types, counts, CSRF-like field names, and sensitive-looking field-name indicators without storing input values or hidden values. `web-scan --forms` checks only the start URL unless `--crawl` is explicitly provided. Form findings are passive indicators for human review and do not submit forms, authenticate, send payloads, fuzz, or test SQL injection or XSS.

Version 13.4 adds `scanner.web_passive_summary`, a consolidated passive Web DAST overview. `web-scan --passive-summary` combines available crawler, header, cookie, and form indicators into `web_passive_summary`, grouped severity indicators, a highest web risk, passive risk rating, recommended next steps, and limitations. When used alone it fetches only the start URL and runs safe passive checks for headers, cookies, and basic form discovery. It does not crawl beyond the start URL unless `--crawl` is provided, submit forms, authenticate, send payloads, fuzz, test SQL injection, test XSS, or prove exploitability.

Version 13.5 adds `scanner.web_scope`, a scope decision layer used by the Web DAST crawler and passive checks. Same-host scope remains the default, external domains are skipped unless explicitly allowed, and users can configure repeated `--allow-host`, `--deny-host`, `--allow-path`, and `--deny-path` rules plus opt-in `--include-subdomains`. The crawler records skipped URL counts and capped samples under `web_scope_summary` and `skipped_url_samples`, and emits concise standard findings with source `web_scope`. Scope controls are intended to make authorised boundaries explicit before future active testing; they do not add exploitation, authentication, form submission, fuzzing, SQL injection testing, or XSS testing.

Version 13.6 adds `scanner.web_rate_limit`, a shared polite request layer for Web DAST. It validates request delay, request-per-minute, retry, backoff, and maximum-error settings; applies pacing before each safe GET request; retries only bounded safe GET failures for timeout, connection error, HTTP 429, and HTTP 503; respects `Retry-After` by default; and stops the crawl when the configured error threshold is reached. Results are reported under `web_politeness_summary` and capped `request_error_samples`, with concise standard findings using source `web_rate_limit`. Header, cookie, form, and passive summary analysis continue to reuse crawler page data and do not add extra requests.

Version 13.7 adds `scanner.web_robots`, an advisory robots.txt awareness layer. When `web-scan --robots` is used, VulScan fetches `/robots.txt` once from the start URL origin through the existing safe request wrapper, parses it with standard-library robot parsing plus safe summary extraction, and reports `web_robots_summary`. `--respect-robots` is the default when enabled, so disallowed URLs are skipped and counted as `skipped_by_robots` in the scope summary. `--no-respect-robots` reports robots guidance without enforcing it and emits a standard informational finding. robots.txt is never treated as authorisation and does not add active testing, exploitation, authentication, form submission, fuzzing, SQL injection testing, or XSS testing.

Version 13.8 adds `scanner.web_sitemap`, a passive sitemap discovery layer. When `web-scan --sitemap` is used, VulScan discovers sitemap files from robots.txt `Sitemap` lines, common same-origin sitemap paths, and repeated `--sitemap-url` values. Sitemap fetches use the shared safe request wrapper and rate limiter, XML parsing uses the Python standard library, and nested sitemap indexes are bounded by `--max-sitemap-depth` and `--max-sitemap-urls`. Sitemap URLs are never treated as authorisation; sitemap files and URL entries are filtered through `scanner.web_scope`, robots rules are respected when enabled, and sitemap-assisted crawling is disabled unless `--use-sitemap-for-crawl` is explicitly provided. Reports include `web_sitemap_summary`, `web_sitemap_results`, `web_sitemap_url_samples`, and concise standard findings with source `web_sitemap`. Version 13.8 does not add active testing, exploitation, authentication, form submission, fuzzing, SQL injection testing, or XSS testing.

The scanner still preserves `open_ports` separately because open ports are useful as asset inventory even when they do not represent confirmed vulnerabilities.
