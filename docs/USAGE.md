# VulScan Usage

VulScan is for authorised defensive vulnerability assessment only.

## TCP Port Scan

From the project root in PowerShell, activate the virtual environment first:

```powershell
.\.venv311\Scripts\Activate.ps1
```

Then run:

```powershell
python -m scanner.main scan --target 127.0.0.1
```

Or use the included helper script:

```powershell
.\run_scan.ps1
```

The Version 11 scanner performs TCP connect checks against a fixed default list of common ports and identifies likely services from a safe static port mapping:

```text
21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443
```

Only open ports are shown by default. Each open result includes the host, resolved IP address, TCP port, protocol, service, status, confidence, evidence, and a defensive recommendation. For example, an open `445/tcp` result is identified as `smb`.

## Findings

VulScan reports include a standard top-level `findings` section. Findings include sequential IDs, severity, category, affected host/port/URL, service, evidence, confidence, impact, recommendation, verification, limitation, source, risk score, risk label, fix priority, and creation time.

Open ports remain in `open_ports` for asset inventory. Open services also create informational service exposure findings.

## Vulnerability Intelligence

Version 14.2 supports optional local vulnerability intelligence matching:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --vuln-intel
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --vuln-intel --vuln-rules data\vuln_intel\sample_vuln_rules.json --json --html --save-db
```

`--vuln-intel` builds a normalised `software_inventory` from discovered open ports, service detection, and available credentialed audit metadata. It then evaluates a local JSON rules file. The default rules file is `data\vuln_intel\sample_vuln_rules.json`.

Version 14.2 uses local rules only. It does not fetch live CVE data, EPSS scores, exploit databases, Metasploit modules, or exploit code. Matches are indicators for prioritised manual validation. Service exposure alone does not confirm a vulnerability, and VulScan does not claim a CVE is confirmed unless supplied product/version evidence supports applicability.

Local rules can include version conditions such as `version_less_than`, `version_greater_than`, and `version_between`. Version-specific rules require local product and version evidence. Unknown versions are not treated as confirmed matches unless the rule explicitly sets `allow_unknown_version: true`, in which case findings are low-confidence indicators.

Reports include `software_inventory`, `vulnerability_intelligence`, and standard findings with source `vuln_intel`. See `docs\VULNERABILITY_INTELLIGENCE.md` for the rule format.

## Risk Scoring

Risk scores are heuristic and range from 0 to 100. They combine severity, confidence, finding source, and exposure context such as sensitive ports or clear-text services.

Risk scores help with triage, but they are not a final statement of business risk. A human reviewer should validate context, asset criticality, exposure, compensating controls, and operational impact before prioritising remediation.

## Scan History

Use `--save-db` to store scan results in the local SQLite database at `data\vulscan.db`:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --save-db
```

View previous scans for a target:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main history --target 127.0.0.1
```

Limit the number of history rows shown:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main history --target 127.0.0.1 --limit 5
```

The history command shows the database path, target, number of scans shown, scan summaries, and latest-scan severity and risk-label counts. If the database does not exist, required tables are missing, or a target has no saved scans, VulScan prints a friendly message.

The database is local to your workstation and should not be committed to Git. It supports future scan diffing, remediation tracking, and trend reporting.

## Scan Diffing

Version 10.2 can compare the latest two saved scans for the same target using the local SQLite database.

Save at least two scans:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --save-db
```

Then compare them:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main diff --target 127.0.0.1
```

The diff command shows the database path, previous and latest scan times, finding totals, total risk score trend, and counts for new, fixed, unchanged, and changed-risk findings. It uses stable finding fingerprints based on title, affected host, affected port, affected URL, service, category, and source.

If the database does not exist, a target has no saved scans, only one saved scan exists, or no findings are available to compare, VulScan prints a friendly message.

## Remediation Status Tracking

Version 10.3 adds remediation status tracking for saved findings. When a scan is saved with `--save-db`, VulScan creates remediation records for new findings with status `Open` and updates `last_seen` for existing findings. Existing status, owner, and note values are preserved. If a finding marked `Fixed` appears again, VulScan reopens it as `Open`.

Save scan results first:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --save-db
```

List remediation records for a target:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main remediation list --target 127.0.0.1
```

Show remediation status counts:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main remediation summary --target 127.0.0.1
```

Update a finding by full or unique short fingerprint:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main remediation update --fingerprint ABC123 --status "In Progress" --owner "Sandesh" --note "Reviewing exposure"
```

Allowed remediation status values are `Open`, `In Progress`, `Fixed`, `Accepted Risk`, and `False Positive`.

## Asset Inventory

Version 10.4 tracks discovered assets and services in the local SQLite database at `data\vulscan.db`. Asset records are created or updated only when a scan is saved with `--save-db`.

Save a scan first:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --save-db
```

List all saved assets:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main assets
```

Show one target with detected services:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main assets --target 127.0.0.1
```

Asset inventory tracks target, resolved IP, first seen, last seen, scan count, latest open-port count, latest finding count, highest risk label, exposure summary, and detected services. It supports future dashboard views, exposure management, trend reporting, and asset criticality workflows.

## Exports

Version 10.5 exports saved SQLite data to CSV or JSON files in the `exports` folder. Exports are generated from local data in `data\vulscan.db`; run scans with `--save-db` first. The `exports` folder is ignored by Git.

CSV exports are useful for Excel and spreadsheet review. JSON exports are useful for APIs, dashboards, and automation.

Export assets:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main export assets --format csv
.\.venv311\Scripts\python.exe -m scanner.main export assets --format json
```

Export scan history for one target, or omit `--target` to export all history:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main export history --target 127.0.0.1 --format csv
.\.venv311\Scripts\python.exe -m scanner.main export history --target 127.0.0.1 --format json
```

Export findings:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main export findings --target 127.0.0.1 --format csv
.\.venv311\Scripts\python.exe -m scanner.main export findings --format json
```

Export remediation records:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main export remediation --target 127.0.0.1 --format csv
.\.venv311\Scripts\python.exe -m scanner.main export remediation --format json
```

## HTTP Security Header Audit

HTTP auditing is optional and runs only when `--http-audit` is provided. It only targets detected web services on `80`, `443`, `8080`, and `8443`, and sends a normal HTTP GET request to `/`.

```powershell
python -m scanner.main scan --target example.com --http-audit
```

To include HTTP findings in both JSON and HTML reports:

```powershell
python -m scanner.main scan --target example.com --http-audit --json --html
```

The HTTP audit checks for common missing security headers, basic information disclosure headers, and basic cookie flags when `Set-Cookie` is present.

## TLS Certificate Audit

TLS auditing is optional and runs only when `--tls-audit` is provided. It only targets detected HTTPS services on `443` and `8443`, and performs a normal TLS handshake to inspect certificate information.

```powershell
python -m scanner.main scan --target example.com --tls-audit
```

To include TLS findings in both JSON and HTML reports:

```powershell
python -m scanner.main scan --target example.com --tls-audit --json --html
```

The TLS audit checks certificate validation status, hostname mismatch where possible, certificate expiry, certificates expiring within 30 days, subject, issuer, and validity dates. It does not test weak ciphers, perform downgrade testing, or run aggressive TLS probing.

## Web DAST Crawler

Version 13.0 adds the Web DAST crawler foundation as a separate `web-scan` command. It is for authorised web applications only and sends safe, bounded GET requests. It does not authenticate, submit forms, fuzz, test SQL injection, test XSS, or send attack payloads.

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://example.com --crawl
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://example.com --crawl --max-pages 10 --max-depth 1 --json --html
```

Crawler options:

- `--url` is required and must be an absolute `http` or `https` URL.
- `--crawl/--no-crawl` controls whether same-host links are followed. Crawling is enabled by default.
- `--max-pages` defaults to `20`.
- `--max-depth` defaults to `2`.
- `--timeout` defaults to `10` seconds per request.
- `--user-agent` defaults to `VulScan-WebDAST/13.0`.

The crawler only follows same-host links by default, ignores fragments, skips unsafe schemes such as `mailto:`, `tel:`, `javascript:`, `data:`, and `file:`, and skips common static/binary files. Reports include `web_scan_summary`, `crawled_pages`, `discovered_forms`, and standard findings. Forms are discovered and reported, but never submitted.

Version 13.1 adds passive header checks to `web-scan` with `--headers`:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --headers
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --headers --max-pages 10 --max-depth 1 --json --html
```

When `--headers` is used with crawling, VulScan checks each crawled same-host page. When `--headers` is used with `--no-crawl`, VulScan checks only the start URL. Header checks are passive and review response headers already collected by the crawler. They check for common browser security headers plus `Server` and `X-Powered-By` disclosure. Missing headers are configuration indicators, not proof of exploitability. Cookie attribute analysis is reported separately under the Web Cookie Audit section.

Version 13.2 adds focused cookie auditing with `--cookies`:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --cookies
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --cookies --max-pages 10 --max-depth 1 --json --html
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --headers --cookies --max-pages 10 --max-depth 1 --json --html
```

Cookie audit parses `Set-Cookie` headers and stores only cookie names and attributes. It does not store cookie values, session IDs, or tokens. It checks Secure, HttpOnly, SameSite, SameSite=None with Secure, and persistent cookie indicators. When `--cookies` is used without explicit `--crawl`, VulScan checks only the start URL. Cookie findings are indicators and should be reviewed in application context.

Version 13.3 adds enhanced form discovery with `--forms`:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --forms
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --forms --max-pages 10 --max-depth 1 --json --html
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --headers --cookies --forms --max-pages 10 --max-depth 1 --json --html
```

Form discovery maps methods, action URLs, internal/external action hosts, HTTPS-to-HTTP submission indicators, input names and types, CSRF-like field names, and classifications such as login, search, contact, upload, newsletter, or generic forms. Forms are never submitted, no payloads are sent, no SQL injection or XSS testing is performed, and field values or hidden values are not stored.

Version 13.4 adds a consolidated passive web risk summary with `--passive-summary`:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --passive-summary
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --headers --cookies --forms --passive-summary --max-pages 10 --max-depth 1 --json --html
```

The summary combines available crawler, header, cookie, and form indicators into `web_passive_summary` and a Web Passive Risk Overview in HTML reports. If `--passive-summary` is used alone, VulScan fetches only the start URL, runs passive header and cookie checks, and performs basic form discovery on that page only. It does not submit forms, authenticate, test SQL injection, test XSS, send payloads, fuzz, crawl external domains, or prove exploitability. Use it to plan authorised deeper testing where in scope.

Version 13.5 adds Web DAST scope and allowlist controls:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --show-scope
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --allow-host www.example.com --max-pages 10
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --allow-path /docs --deny-path /logout --headers --cookies --forms --passive-summary --json --html
```

Same-host crawling remains the default. External domains are skipped unless explicitly allowed with `--allow-host` or, where authorised, `--include-subdomains`. `--deny-host` blocks specific hosts, `--allow-path` limits crawling and passive checks to path prefixes, and `--deny-path` blocks path prefixes. JSON and HTML reports include `web_scope_summary` and capped `skipped_url_samples`. Scope rules should be reviewed before deeper authorised testing.

Version 13.6 adds Web DAST rate limiting and politeness controls:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --request-delay 1
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --max-requests-per-minute 30 --retry-limit 1 --max-errors 5
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --headers --cookies --forms --passive-summary --max-pages 10 --max-depth 1 --request-delay 1 --json --html
```

The default request delay is `0.5` seconds and the default cap is `60` requests per minute. `--retry-limit` defaults to `1`, `--retry-backoff` defaults to `2.0`, and `--max-errors` defaults to `10`. VulScan respects `Retry-After` by default and records `web_politeness_summary` plus capped `request_error_samples` in JSON and HTML reports. This is still passive scanning only; tune limits only within written authorisation.

Version 13.7 adds robots.txt awareness:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --robots
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --robots --respect-robots --max-pages 10 --max-depth 1
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --robots --no-respect-robots --headers --cookies --forms --passive-summary --json --html
```

When `--robots` is enabled, VulScan fetches `robots.txt` once from the start URL origin and reports `web_robots_summary`. `--respect-robots` is the default, so disallowed URLs are skipped and counted in scope data. `--no-respect-robots` reports robots guidance without enforcing it and should be used only when written authorisation explicitly allows it. robots.txt is advisory, is not authorisation, and sitemap URLs must still remain in scope.

Version 13.8 adds passive sitemap discovery:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --sitemap
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --robots --sitemap
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --sitemap --sitemap-url https://example.com/sitemap.xml
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --sitemap --use-sitemap-for-crawl --max-pages 20 --max-depth 1 --json --html
```

Sitemap discovery checks robots.txt sitemap references, common same-origin sitemap paths, and explicit `--sitemap-url` values. Sitemaps do not grant authorisation; all sitemap files and URL entries are filtered by scope, and robots rules still apply when enabled. Sitemap-assisted crawling is off by default and requires `--use-sitemap-for-crawl`. It remains passive discovery only and does not add SQL injection, XSS, form submission, authentication, fuzzing, or exploitability testing.

Version 13.9 consolidates passive Web DAST reporting:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --robots --sitemap --headers --cookies --forms --passive-summary --max-pages 10 --max-depth 1 --request-delay 1 --show-scope --json --html
```

The consolidated report adds `web_dast_summary` and `web_dast_sections` while keeping existing web report keys. It combines scope, politeness, robots, sitemap, crawler, headers, cookies, forms, and passive risk indicators into compact terminal, JSON, and HTML output. It does not add active vulnerability testing, does not submit forms, does not authenticate, does not test SQL injection or XSS, and does not prove exploitability. Written authorisation is still required before scanning or deeper testing.

## Authenticated SSH Audit

Version 11.5 includes optional authenticated SSH auditing for authorised Linux systems only. It runs only when `--ssh-audit` is provided and requires a username plus either a password or a private key. VulScan does not prompt interactively for passwords.

Use least-privilege read-only credentials:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 192.168.1.143 --ssh-audit --ssh-user USER --ssh-password PASSWORD
.\.venv311\Scripts\python.exe -m scanner.main scan --target 192.168.1.143 --ssh-audit --ssh-user USER --ssh-key PATH_TO_PRIVATE_KEY
.\.venv311\Scripts\python.exe -m scanner.main scan --target 192.168.1.143 --ssh-audit --ssh-user USER --ssh-key PATH_TO_PRIVATE_KEY --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --audit-profile basic
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --audit-profile standard
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --audit-profile detailed --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --audit-profile basic --ssh-timeout 8 --ssh-command-timeout 10
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --audit-profile detailed --ssh-audit-timeout 90 --json --html --save-db
```

Use `--ssh-port` if SSH is listening on a non-standard port. The default is `22`.

Use SSH timeout options to tune slow or unreliable authorised targets:

- `--ssh-timeout`: SSH connection timeout in seconds. Default `8`. Valid range: greater than `0` and no more than `60`.
- `--ssh-command-timeout`: timeout for each remote read-only command. Default `10`. Valid range: greater than `0` and no more than `120`.
- `--ssh-audit-timeout`: overall post-login SSH audit budget. Defaults by profile: `basic` `30`, `standard` `60`, `detailed` `90`. Valid range: greater than `0` and no more than `600`.
- `--ssh-progress` / `--no-ssh-progress`: show or suppress compact terminal progress messages. Progress is terminal-only and is not embedded as noisy output in JSON or HTML reports.

Use `--audit-profile` to choose the depth of read-only credentialed checks. Profiles apply only when `--ssh-audit` is used:

- `basic`: SSH login verification, OS information, hostname, kernel summary, and SSH hardening review.
- `standard`: default profile; includes `basic` plus package manager detection, package update checks, firewall indicators, and logging indicators.
- `detailed`: includes `standard` plus password policy indicators, temporary directory sticky-bit checks, and cleartext service exposure indicators.

All profiles are read-only. The `detailed` profile runs more checks and may take slightly longer.

The SSH audit attempts one login using the credentials explicitly provided for that scan. Passwords, key values, and private key paths are not stored in reports, the SQLite database, logs, or terminal output. SSH audit results are stored as sanitized audit status, command results, a top-level `ssh_audit_summary`, and standard findings.

When `--ssh-audit` is used, the terminal output includes progress messages and a **Credentialed SSH Audit Summary** before the general findings. JSON and HTML reports include a top-level SSH audit summary with authentication status, username, auth method, audit profile, enabled/skipped checks, timeout settings, total SSH audit duration, completed/failed/skipped checks, timed-out command count, slowest command metadata, OS family, hostname, kernel summary, package indicators, SSH hardening status, Linux configuration status, total SSH findings, highest SSH risk, and limitations. SSH findings are grouped by source in terminal output, including `ssh_audit`, `package_audit`, `ssh_hardening`, and `linux_config_audit`.

Version 11.6 adds structured SSH audit error handling. If authentication fails, the SSH target times out, a key file is missing, or an individual read-only command cannot complete, VulScan returns safe status fields such as `success`, `failed`, `skipped`, or `partial` with a short error code and message. Partial command failures do not crash the scan; VulScan continues other read-only checks where safe. Technical details are sanitized and credentials are not stored or printed.

Version 11.8 adds credentialed audit performance controls. Commands record duration and timeout status. If one non-critical command fails or times out, the SSH audit can return `partial` while preserving completed findings. If the overall audit budget is exceeded after login, VulScan skips remaining checks, records `SSH_AUDIT_TIME_BUDGET_EXCEEDED`, and returns partial results instead of aborting the whole scan.

Version 11.9 normalises credentialed audit results internally. SSH audit output still includes the user-friendly `ssh_audit_summary`, but reports also include a top-level `credentialed_audits` list with standard fields for module name, source, status, target, authentication method, username, profile, check counts, findings, errors, limitations, performance, and metadata. Passwords, private key contents, and private key paths are not stored in this normalised result. This prepares VulScan for future Windows SMB/WinRM audit modules without changing existing commands.

Version 12.6 adds opt-in narrow read-only Windows registry audit templates on top of the Windows SMB/WinRM audit foundation, WinRM authentication validation, host information collection, Firewall/Defender status collection, and `net accounts` local security policy indicators. Foundation checks still use safe TCP socket reachability only for SMB `445`, NetBIOS/SMB `139`, WinRM HTTP `5985`, WinRM HTTPS `5986`, and RDP `3389`.

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --windows-audit
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-auth-method none
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-user USER --windows-password PASSWORD --windows-domain WORKGROUP --windows-auth-method smb
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-user USER --windows-password PASSWORD --windows-auth-method winrm --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-user USER --windows-password PASSWORD --windows-auth-method winrm --windows-host-info --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-user USER --windows-password PASSWORD --windows-auth-method winrm --windows-security-status --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-user USER --windows-password PASSWORD --windows-auth-method winrm --windows-policy-status --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-user USER --windows-password PASSWORD --windows-auth-method winrm --windows-registry-audit --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-user USER --windows-password PASSWORD --windows-auth-method winrm --windows-registry-audit --windows-registry-template templates\windows_registry\basic_security_indicators.json
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-user USER --windows-password PASSWORD --windows-auth-method winrm --windows-host-info --windows-security-status --windows-patch-status --windows-policy-status --windows-registry-audit --json --html --save-db
```

Allowed `--windows-auth-method` values are `none`, `smb`, and `winrm`; the default is `none`. WinRM authentication requires both `--windows-user` and `--windows-password`; VulScan does not prompt interactively and does not store or print the password. `--windows-host-info`, `--windows-security-status`, `--windows-policy-status`, and `--windows-registry-audit` also require `--windows-audit`, `--windows-auth-method winrm`, `--windows-user`, and `--windows-password`. `--windows-registry-template` applies only when `--windows-registry-audit` is enabled.

WinRM endpoint selection uses the reachability results: HTTPS `5986` is preferred, then HTTP `5985`. VulScan uses `pywinrm` if it is installed. If `pywinrm` is missing, the scan records `WINRM_DEPENDENCY_MISSING` and continues without a crash. The validation runs one harmless read-only command such as `hostname`.

When `--windows-host-info` is provided and authentication succeeds, VulScan runs only safe read-only PowerShell commands for hostname, current identity, PowerShell version, operating system caption/version/build/architecture/boot/install dates, computer system domain/workgroup/manufacturer/model, and timezone. It does not query registry or security policy, enumerate users, groups, files, processes, shares, patches, secrets, browser data, hashes, tokens, or private keys, dump credentials, perform privilege checks, or modify systems. Host information supports future Windows patch, policy, Defender, and firewall checks. For lab HTTPS endpoints with self-signed certificates, certificate validation may be relaxed and this is recorded as a limitation.

When `--windows-security-status` is provided and authentication succeeds, VulScan runs only safe read-only PowerShell commands for `Get-NetFirewallProfile`, `Get-Service WinDefend`, and `Get-MpComputerStatus`. It does not use `Set-NetFirewallProfile`, `Set-MpPreference`, start or stop services, change Defender settings, change firewall rules, enumerate individual firewall rules, query registry, or query local security policy. `Get-MpComputerStatus` may be unavailable or permission-restricted on some systems; VulScan records partial status instead of crashing. Defender disabled may be expected if approved third-party EDR/AV is used.

When `--windows-policy-status` is provided and authentication succeeds, VulScan runs only `net accounts` over WinRM and parses minimum password length, maximum password age, password history length, lockout threshold, lockout duration, lockout observation window, force logoff, and computer role where available. It does not run `secedit /export`, `gpresult`, registry queries, local user enumeration, local group enumeration, password reset commands, account modification commands, or policy modification commands. `net accounts` is an indicator; domain Group Policy or enterprise identity controls may override or affect local values, and VulScan does not perform full Group Policy analysis.

When `--windows-registry-audit` is provided and authentication succeeds, VulScan loads a JSON template and queries only exact `HKLM` paths and value names listed in that template using read-only PowerShell registry access. Version 12.6 does not support `HKCU`, wildcard paths, recursive registry enumeration, `reg save`, `reg export`, `Set-ItemProperty`, `New-ItemProperty`, or registry modification. Missing values are reported cautiously as unknown/not present and may be normal on some Windows versions. Registry indicators should be reviewed with service exposure and policy context.

Windows audit results include `windows_audit_summary`, optional `windows_host_info`, optional `windows_security_status`, optional `windows_policy_status`, optional `windows_registry_audit`, standard findings with source `windows_audit`, `windows_security_audit`, `windows_policy_audit`, or `windows_registry_audit`, and a normalised `credentialed_audits` entry. Version 12.6 does not exploit, brute force, enumerate shares, dump credentials, modify systems, restart services, or validate vulnerabilities. WinRM should be restricted to trusted networks.

Version 12.8 improves Windows audit evidence quality and redaction. VulScan stores concise evidence summaries for Windows and SSH findings instead of full raw command output by default. JSON and HTML reports can include safe `evidence_details` such as source, observed value, expected value, and limitation. Raw PowerShell output is not stored in findings by default, Windows hotfix samples are limited, and report/export data is redacted for password, token, authorization header, private key, hash, and credential-like patterns. Evidence is intended to support remediation and verification, and should still be reviewed in operational context. Users should avoid placing real credentials in shell history where possible.

Version 12.9 adds Windows audit timeout and progress controls. `--windows-timeout` defaults to `10` seconds for WinRM connection/session handling, `--windows-command-timeout` defaults to `15` seconds per read-only Windows command, and `--windows-audit-timeout` defaults to `120` seconds for the overall Windows audit budget after authentication. Values must be greater than zero and within safe upper bounds. If a section fails, times out, or is skipped because the audit budget is exhausted, VulScan preserves successful section results and returns a partial Windows audit rather than failing the whole scanner. Terminal progress is shown by default with `--windows-progress` and can be disabled with `--no-windows-progress`; progress messages are not added as noisy report content. Tests use mocks and do not require a live Windows target.

Version 12.10 normalises Windows audit output internally. When `--windows-audit` is used, JSON and HTML reports include `windows_audit_sections` alongside the existing `windows_audit_summary`, `windows_audit_consolidated_summary`, `credentialed_audits`, and `findings` keys. Each section records a stable section ID, section name, source, status, check counts, findings, safe errors, limitations, and performance metadata for service reachability, WinRM authentication, host information, security status, patch status, local security policy, and registry audit. The consolidated Windows summary is built from these sections where available. Existing commands and report keys remain backward compatible, and normalised results avoid passwords, secrets, private keys, tokens, hashes, and raw command output by default. This prepares VulScan for future Windows audit profiles, dashboards, and API integration.

Version 12.11 adds Windows audit profiles with `--windows-audit-profile foundation|standard|detailed`. Profiles apply only with `--windows-audit`; `standard` is the default. `foundation` is fastest and runs service reachability plus WinRM authentication validation only when `--windows-auth-method winrm` and credentials are provided. `standard` adds read-only host information, Firewall/Defender status, and patch/update indicators when WinRM is available. `detailed` adds read-only local security policy indicators and the default narrow registry audit template. Manual flags such as `--windows-registry-audit` can extend a selected profile; they do not disable sections already selected by the profile. All profile-driven Windows checks remain read-only, and passwords are not stored or printed.

Version 12.12 adds Windows demo mode for screenshots, report validation, and portfolio use:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target demo-windows --windows-audit --windows-demo
.\.venv311\Scripts\python.exe -m scanner.main scan --target demo-windows --windows-audit --windows-demo --windows-audit-profile detailed --json --html
.\.venv311\Scripts\python.exe -m scanner.main scan --target demo-windows --windows-audit --windows-demo --json --html --save-db
```

Demo mode uses fake sample data only. It does not connect to any host, run socket checks, require WinRM, or require credentials. Terminal, JSON, and HTML output are clearly marked with `demo_mode: true` and `Demo data only. No real target was scanned.` Demo reports should not be used for real security decisions.

After login, VulScan runs read-only Linux inspection commands only: `uname -a`, `cat /etc/os-release`, `sshd -T` when available, firewall status checks when available, package-manager discovery, package update checks, and Linux configuration indicator checks. It does not run `sudo`, change files, install packages, update packages, restart services, fuzz, crawl, exploit, brute force, guess passwords, or attempt privilege escalation.

Package manager detection checks `apt`, `apt-get`, `dnf`, `yum`, `pacman`, and `zypper` with `command -v`. VulScan derives the Linux family from `/etc/os-release` and reports Debian/Kali/Parrot/Ubuntu, Fedora/RHEL/Rocky/Alma, Arch, openSUSE/SUSE, or Unknown Linux.

Package update checks are read-only:

```text
apt list --upgradable
dnf check-update
yum check-update
pacman -Qu
zypper list-updates
```

For apt-based systems, VulScan does not run `apt update`; `apt list --upgradable` depends on the package metadata already available on the host. Package findings support patch management review by reporting detected package manager details, update counts, and a sample of up to 20 package names. This does not replace full vulnerability intelligence, CVE enrichment, vendor advisories, asset criticality, or change-management review.

Linux configuration audit templates are also read-only. VulScan reviews available firewall indicators, audit/logging service status, local password policy indicators from `/etc/login.defs` and `/etc/security/pwquality.conf`, sticky-bit indicators for `/tmp` and `/var/tmp`, cleartext service exposure indicators from existing service detection, and basic hostname/OS information.

These checks are indicators and should be reviewed in operational context. They may not reflect all PAM settings, central identity provider policy, central logging agents, cloud firewall controls, or enterprise hardening exceptions. This is not a full CIS benchmark implementation yet, but it prepares the framework for CIS-style audit templates.

SSH audit can reduce false positives by checking system configuration directly. Unsupported or non-Linux systems are handled safely by stopping Linux-specific checks when Linux OS details are not available. Windows SMB/WinRM auditing currently provides safe reachability checks, optional WinRM authentication validation, optional basic host information collection, optional Firewall/Defender status collection, and optional `net accounts` local security policy indicators.

## Windows Example

```powershell
python -m scanner.main scan --target 127.0.0.1
```

To save a JSON report in the `reports` folder:

```powershell
python -m scanner.main scan --target 127.0.0.1 --json
```

To save an HTML report in the `reports` folder:

```powershell
python -m scanner.main scan --target 127.0.0.1 --html
```

To save both JSON and HTML reports:

```powershell
python -m scanner.main scan --target 127.0.0.1 --json --html
```

Equivalent explicit virtual environment commands:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --json --html
.\.venv311\Scripts\python.exe -m scanner.main scan --target example.com --http-audit --tls-audit --json --html
.\.venv311\Scripts\python.exe -m scanner.main scan --target 192.168.1.143 --ssh-audit --ssh-user USER --ssh-key PATH_TO_PRIVATE_KEY --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main assets
.\.venv311\Scripts\python.exe -m scanner.main assets --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main history --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main history --target 127.0.0.1 --limit 5
.\.venv311\Scripts\python.exe -m scanner.main diff --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main remediation list --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main remediation summary --target 127.0.0.1
.\.venv311\Scripts\python.exe -m scanner.main remediation update --fingerprint ABC123 --status "In Progress" --owner "Sandesh" --note "Reviewing exposure"
.\.venv311\Scripts\python.exe -m scanner.main export assets --format csv
.\.venv311\Scripts\python.exe -m scanner.main export history --target 127.0.0.1 --format json
.\.venv311\Scripts\python.exe -m scanner.main export findings --target 127.0.0.1 --format csv
.\.venv311\Scripts\python.exe -m scanner.main export remediation --format json
```

To run HTTP auditing and save reports:

```powershell
python -m scanner.main scan --target example.com --http-audit --json --html
```

To run TLS auditing and save reports:

```powershell
python -m scanner.main scan --target example.com --tls-audit --json --html
```

Example output includes a table with:

```text
Port  Protocol  Service  Status  Evidence  Recommendation
```

When `--json` is used, VulScan also prints the saved report path:

```text
JSON report saved: reports\127.0.0.1_2026-05-12_231500.json
```

When `--html` is used, VulScan also prints the saved report path:

```text
HTML report saved: reports\127.0.0.1_2026-05-13_231500.html
```

## Installing Dependencies

After activating `.venv311`, install the project requirements from PowerShell:

```powershell
python -m pip install -r requirements.txt
```

## Running Tests

Run tests from the project root with:

```powershell
.\.venv311\Scripts\python.exe -m pytest
```

SSH audit tests use fake fixtures in `tests\fixtures` and mocked command output. They do not require internet access, a live SSH server, or real credentials. Runtime SSH testing still requires authorised Linux credentials. Test fixtures must not contain real passwords, private keys, tokens, host secrets, or personal data.

## Safety Boundaries

Do not use VulScan against systems you do not own or do not have explicit permission to test. VulScan does not perform SYN scanning, UDP scanning, stealth scanning, crawling, fuzzing, brute forcing, credential attacks, password guessing, exploitation, payload attacks, firewall bypassing, cipher probing, protocol downgrade testing, privilege escalation, or destructive actions.
