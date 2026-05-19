# VulScan

VulScan is an intermediate-level defensive vulnerability scanner and auditing tool for authorised use.

Current capabilities include safe TCP connect scanning, service detection, JSON and HTML reports, HTTP security header checks, a safe Web DAST crawler foundation with passive headers, cookies, forms, risk summary, scope controls, rate limiting, robots.txt awareness, and sitemap discovery, TLS certificate checks, SQLite history, scan diffing, remediation tracking, asset inventory, exports, and optional authenticated SSH auditing for authorised Linux systems with read-only audit profiles, package checks, and configuration checks.
Version 12.6 also includes Windows SMB/WinRM audit foundation checks, optional single-attempt WinRM authentication validation, opt-in read-only Windows host information collection, opt-in Windows Firewall and Microsoft Defender status collection, opt-in local security policy indicators from `net accounts`, and narrow template-based registry indicators using explicitly provided credentials.

## Requirements

- Windows 11
- PowerShell
- Python 3.11
- Virtual environment: `.venv311`

Dependencies are listed in `requirements.txt`.

## Windows Setup

From the project root in PowerShell:

```powershell
.\.venv311\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, allow scripts for the current user and then activate again:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\.venv311\Scripts\Activate.ps1
```

## Usage

From the project root with `.venv311` activated:

```powershell
python -m scanner.main scan --target 127.0.0.1
```

Optional authenticated SSH audit for an authorised Linux system:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 192.168.1.143 --ssh-audit --ssh-user USER --ssh-password PASSWORD
.\.venv311\Scripts\python.exe -m scanner.main scan --target 192.168.1.143 --ssh-audit --ssh-user USER --ssh-key PATH_TO_PRIVATE_KEY
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --audit-profile basic
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --audit-profile detailed --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target KALI_IP --ssh-audit --ssh-user USER --ssh-password PASSWORD --audit-profile basic --ssh-timeout 8 --ssh-command-timeout 10
```

SSH audit uses one explicitly provided login, runs read-only Linux inspection commands only, and does not store SSH passwords, key values, or private key paths. Package and configuration checks are read-only and do not install, update, or modify packages or files. Results are indicators for authorised review, not a full CIS benchmark implementation. Use least-privilege credentials. Windows WinRM authentication validation uses one explicitly provided username/password pair. Optional Windows collection runs only safe read-only commands for host information, Firewall profile status, WinDefend service status, Defender computer status, local policy indicators from `net accounts`, and exact registry values defined by a template. VulScan does not store or print the Windows password.

Credentialed SSH audit output includes a sanitized summary in terminal, JSON, and HTML reports. Passwords, key values, and private key paths are never included. Audit profiles apply only with `--ssh-audit`: `basic` is fastest with a 30 second default audit budget, `standard` is the default with 60 seconds, and `detailed` runs additional read-only configuration indicators with 90 seconds.

SSH audit timeout options are `--ssh-timeout`, `--ssh-command-timeout`, and `--ssh-audit-timeout`. SSH audit error handling reports safe status and error-code fields for authentication failures, timeouts, missing key files, unsupported targets, partial command failures, and audit budget exhaustion. Partial results keep completed findings and count skipped checks. Tests use fake fixtures and mocked SSH behavior; they do not require a live SSH server or real credentials.

Credentialed audit findings store concise evidence summaries, not full raw SSH or PowerShell output by default. Evidence is designed for reporting and remediation, includes safe observed/expected values in JSON and HTML reports where useful, and redacts values that look like passwords, tokens, private keys, authorization headers, hashes, or credential-like strings. JSON, HTML, and export paths apply redaction before writing reports; users should still avoid placing real credentials in command history where possible.

Credentialed audit results are normalised internally under `credentialed_audits` in JSON and HTML reports. Existing SSH summaries remain available, and existing commands are unchanged. The normalised model avoids storing passwords, private key contents, or private key paths and prepares VulScan for future Windows SMB/WinRM audit modules.

Windows audit foundation examples:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --windows-audit
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-auth-method none
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-user USER --windows-password PASSWORD --windows-domain WORKGROUP --windows-auth-method smb --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-auth-method winrm --windows-user USER --windows-password PASSWORD
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-auth-method winrm --windows-user USER --windows-password PASSWORD --windows-host-info
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-auth-method winrm --windows-user USER --windows-password PASSWORD --windows-security-status
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-auth-method winrm --windows-user USER --windows-password PASSWORD --windows-policy-status
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-auth-method winrm --windows-user USER --windows-password PASSWORD --windows-registry-audit
.\.venv311\Scripts\python.exe -m scanner.main scan --target WINDOWS_IP --windows-audit --windows-auth-method winrm --windows-user USER --windows-password PASSWORD --windows-registry-audit --windows-registry-template templates\windows_registry\basic_security_indicators.json
```

Version 12.6 Windows audit checks TCP reachability for SMB, NetBIOS/SMB, WinRM HTTP, WinRM HTTPS, and RDP. With `--windows-auth-method winrm`, it requires `--windows-user` and `--windows-password`, prefers HTTPS on 5986 over HTTP on 5985, uses `pywinrm` when installed, and performs one safe read-only validation command. With `--windows-registry-audit`, it queries only exact HKLM registry paths and value names defined in `templates\windows_registry\basic_security_indicators.json` or a provided template. It does not modify registry values, write to registry, query broad registry trees, export registry hives, enumerate users, collect secrets, exploit, brute force, modify systems, or restart services. Missing registry values may be normal on some Windows versions and should be interpreted in context. Passwords are not stored or printed.

Windows audit timeout tuning is available with `--windows-timeout` (default `10`), `--windows-command-timeout` (default `15`), and `--windows-audit-timeout` (default `120`). Slow or failed Windows sections now return partial results with performance metadata instead of blocking the full scanner. Compact terminal progress is enabled by default and can be disabled with `--no-windows-progress`.

Version 12.10 normalises Windows audit results into `windows_audit_sections` while keeping the existing `windows_audit_summary`, `windows_audit_consolidated_summary`, `credentialed_audits`, and `findings` outputs. The normalised section model avoids secrets and raw command output by default and prepares VulScan for future Windows profiles, dashboards, and API integration without changing existing commands.

Version 12.11 adds Windows audit profiles with `--windows-audit-profile foundation|standard|detailed`. `standard` is the default, `foundation` is fastest, and `detailed` runs additional read-only local policy and registry template indicators. Manual Windows flags can extend the selected profile, and all profiles remain read-only. Windows passwords are not stored or printed.

Version 12.12 adds Windows demo mode with `--windows-demo`. Demo mode uses fake sample data only, does not connect to any host, does not require credentials, and clearly marks terminal, JSON, and HTML output as demo data. Use it for screenshots, report testing, and portfolio demonstrations only; demo reports must not be used for real security decisions. See `docs\DEMO_MODE.md`.

Version 13.0 starts the Web DAST Engine with a safe crawler foundation. It sends bounded same-host GET requests, discovers pages, links, and forms, and reports password/file-upload form indicators without submitting forms or testing SQL injection, XSS, or other payload-based checks. See `docs\WEB_DAST.md`.

Version 13.1 integrates passive Web DAST security header checks with `--headers`. Header checks assess crawled pages or the start URL for common security headers and disclosure headers. They are configuration indicators only and do not submit forms, fuzz, test SQL injection, or test XSS.

Version 13.2 improves cookie auditing with `--cookies`. Cookie values are not stored or printed; VulScan records only cookie names and attributes such as Secure, HttpOnly, SameSite, path, domain, Expires, and Max-Age. Cookie findings are duplicate-safe indicators for authorised review.

Version 13.3 improves form discovery with `--forms`. Forms are mapped and classified without submission, field values and hidden values are not stored, and findings are limited to passive indicators that require human review.

Version 13.4 adds `--passive-summary`, which consolidates crawler, header, cookie, and form indicators into a passive web risk overview. Used alone, it fetches only the start URL and runs safe passive header, cookie, and basic form discovery checks. It does not submit forms, authenticate, test SQL injection, test XSS, send payloads, fuzz, crawl external domains, or prove exploitability.

Version 13.5 adds Web DAST scope and allowlist controls. Same-host crawling remains the default, external domains are skipped unless explicitly allowed, and reports include `web_scope_summary` plus capped skipped URL samples. Use `--allow-host`, `--deny-host`, `--allow-path`, `--deny-path`, `--include-subdomains`, and `--show-scope` to make authorised boundaries explicit before deeper testing.

Version 13.6 adds rate limiting and politeness controls. The default request delay is `0.5` seconds, `Retry-After` is respected by default, and VulScan stops crawling after too many request errors. Reports include `web_politeness_summary` and capped request error samples. This remains passive scanning only.

Version 13.7 adds robots.txt awareness with `--robots`. robots.txt is advisory and is not authorisation to scan. `--respect-robots` is the default when robots awareness is enabled; use `--no-respect-robots` only when written permission explicitly allows it. Sitemaps found in robots.txt must still remain within configured scope.

Version 13.8 adds sitemap discovery with `--sitemap`. Sitemap discovery is passive and does not grant authorisation. VulScan can parse robots.txt sitemap references, common same-origin sitemap paths, and explicit `--sitemap-url` values, but all sitemap URLs are filtered by scope and robots controls when enabled. Sitemap-assisted crawling is off by default and requires `--use-sitemap-for-crawl`; max pages, max depth, scope, robots, and rate limits still apply.

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://example.com --crawl
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://example.com --crawl --max-pages 10 --max-depth 1 --json --html
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --headers --max-pages 10 --max-depth 1 --json --html
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --cookies
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --passive-summary
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --headers --cookies --forms --max-pages 10 --max-depth 1 --json --html
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --headers --cookies --forms --passive-summary --max-pages 10 --max-depth 1 --json --html
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --show-scope
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --allow-host www.example.com --max-pages 10
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --allow-path /docs --deny-path /logout --headers --cookies --forms --passive-summary --json --html
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --request-delay 1
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --max-requests-per-minute 30 --retry-limit 1 --max-errors 5
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --headers --cookies --forms --passive-summary --max-pages 10 --max-depth 1 --request-delay 1 --json --html
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --robots
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --robots --respect-robots --max-pages 10 --max-depth 1
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --robots --no-respect-robots --headers --cookies --forms --passive-summary --json --html
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --sitemap
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --robots --sitemap
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --sitemap --sitemap-url https://example.com/sitemap.xml
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --sitemap --use-sitemap-for-crawl --max-pages 20 --max-depth 1 --json --html
```

You can also use the helper script:

```powershell
.\run_scan.ps1
```

The scanner prints the VulScan version, target, resolved IP, scan mode, safe usage warning, open TCP ports, evidence, and total scan time.

## Tests

Run tests from PowerShell with:

```powershell
.\.venv311\Scripts\python.exe -m pytest
```

## Safety

Use VulScan only on systems and web applications you own or have explicit written permission to assess. This project must remain defensive and must not include exploitation, brute forcing, credential attacks, password guessing, payload attacks, package modification, privilege escalation, or destructive functionality.
