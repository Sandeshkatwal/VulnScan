# VulScan

VulScan is an intermediate-level defensive vulnerability scanner and auditing tool for authorised use.

Current capabilities include safe TCP connect scanning, service detection, local vulnerability intelligence matching, local CVE-style feed import, offline EPSS metadata enrichment, offline exploit availability metadata enrichment, local asset criticality prioritisation, fix-first dashboard reporting, prioritisation trend tracking, a local FastAPI API foundation, JSON and HTML reports, HTTP security header checks, a safe Web DAST crawler foundation with passive headers, cookies, forms, risk summary, scope controls, rate limiting, robots.txt awareness, sitemap discovery, and consolidated passive Web DAST reporting, TLS certificate checks, SQLite history, scan diffing, remediation tracking, asset inventory, exports, and optional authenticated SSH auditing for authorised Linux systems with read-only audit profiles, package checks, and configuration checks.
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

Optional local vulnerability intelligence matching:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --vuln-intel
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --vuln-intel --vuln-rules data\vuln_intel\sample_vuln_rules.json --json --html --save-db
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --vuln-intel --use-cve-feed --cve-feed data\cve_feeds\sample_cve_feed.json
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --vuln-intel --use-cve-feed --use-epss --cve-feed data\cve_feeds\sample_cve_feed.json --epss-file data\epss\sample_epss.csv
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --vuln-intel --use-cve-feed --use-exploit-metadata --cve-feed data\cve_feeds\sample_cve_feed.json --exploit-metadata-file data\exploit_metadata\sample_exploit_metadata.json
```

Version 14.5 adds a local vulnerability intelligence foundation with version-aware rules, optional local CVE-style feed import, offline EPSS metadata enrichment, and offline exploit availability metadata enrichment. It normalises discovered services/software into `software_inventory`, evaluates local JSON rules from `data\vuln_intel\sample_vuln_rules.json` by default, can evaluate local feed records from `data\cve_feeds\sample_cve_feed.json`, can enrich matched CVEs from `data\epss\sample_epss.csv` and `data\exploit_metadata\sample_exploit_metadata.json`, and emits `vuln_intel`, `cve_feed`, or importer status findings through the standard findings pipeline. It does not fetch live CVE, EPSS, Exploit-DB, Metasploit, exploit metadata, or exploit code, and intelligence matches are indicators that require validation. Version-specific rules and feed records require local product/version evidence unless explicitly marked as unknown-version indicators. EPSS and exploit availability are prioritisation signals, not proof of exploitation. See `docs\VULNERABILITY_INTELLIGENCE.md`.

Version 14.7 adds local asset criticality for prioritisation. Use `--prioritise --use-asset-criticality` with either direct criticality or a local JSON mapping:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --prioritise --use-asset-criticality --asset-criticality low
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --prioritise --use-asset-criticality --asset-criticality-file data\asset_context\sample_asset_criticality.json --json --html --save-db
```

Allowed values are `critical`, `high`, `medium`, `low`, and `unknown`. Direct CLI criticality overrides file mappings. Asset criticality is business context only; it is not a vulnerability, does not confirm exploitability, and should be reviewed and maintained. See `docs\PRIORITISATION.md`.

Version 14.8 adds a fix-first dashboard for prioritised findings:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --prioritise --fix-first-dashboard
```

The dashboard adds terminal, JSON, HTML, and export-friendly views for `fix_first_dashboard`, priority distribution, top fix-first findings, a remediation action plan, and an executive summary. It uses existing prioritised findings only; it does not perform new scanning, exploit checks, live attack checks, or internet feed fetching. SLA hints are generic and human validation is still required. See `docs\PRIORITISATION.md`.

Version 14.9 adds prioritisation trend tracking:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --prioritise --fix-first-dashboard --priority-trends --save-db
```

Trend tracking compares current prioritised findings with the latest previous saved scan for the same target and reports baseline, improved, worsened, or stable trend context. Use `--save-db` for useful history. Stable finding keys are intentionally conservative but may not perfectly match renamed findings, so human review is still required. Trend tracking does not perform new scanning, exploit checks, live attack checks, or internet feed fetching. See `docs\PRIORITISATION.md`.

Version 16.2 adds a local React + Vite vulnerability list and finding detail UI on top of the local FastAPI API. The dashboard is local development only, runs on `http://localhost:5173`, and displays API health, safe scan job creation, recent jobs, selected job details, result summaries, recent scans, a read-only vulnerability list, and finding details. Version 16.3 adds a Risk Overview for the selected completed job, using loaded findings and job result data to summarise severity, priority, sources, top risks, asset criticality, and available trend context. Version 16.4 adds a Trends View for prioritisation trend data from completed jobs. Version 16.5 adds a Reports View that reads completed jobs and report paths from the API, lets local users copy JSON/HTML paths, and shows available report metadata. Version 16.6 adds sidebar navigation and layout polish with sections for Overview, Jobs, Vulnerabilities, Risk, Trends, Reports, and Settings. The Settings section shows API URL, API key configured/not configured status without displaying the key, local development mode, backend docs, and OpenAPI links. Start the backend first, then the dashboard. The dashboard remains local, read-only, and free of exploit or credential controls.

```powershell
.\.venv311\Scripts\python.exe -m scanner.main api
$env:VULSCAN_API_KEY="change-this-local-dev-key"
.\.venv311\Scripts\python.exe -m scanner.main api --require-api-key
```

Then start the dashboard:

```powershell
cd dashboard
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

Dashboard configuration lives in `dashboard\.env`, copied from `dashboard\.env.example`:

```text
VITE_VULSCAN_API_URL=http://127.0.0.1:8088
VITE_VULSCAN_API_KEY=
```

Do not commit `.env` or hard-code API keys. If `VITE_VULSCAN_API_KEY` is set, the dashboard sends it as `X-VulScan-API-Key`; otherwise it calls public endpoints and local-development protected endpoints only when the API permits them. The API allows local-only CORS for `http://localhost:5173` and `http://127.0.0.1:5173`; broad origins are not enabled.

The dashboard scan form sends `POST /scans` with `scan_mode` fixed to `safe`. It does not support credentialed scans, SSH passwords, Windows passwords, tokens, private keys, API key entry, exploit options, brute forcing, or active web attack options.

To review findings, select a completed job, load findings, then use search, filters, sorting, and pagination in the vulnerability list. Open a finding detail panel for evidence, impact, recommendation, verification, prioritisation, CVE/CVSS/EPSS metadata, exploit metadata indicators, affected URLs, asset criticality, and remediation status where available. The dashboard is read-only for findings and does not include exploit download or credential controls.

The underlying API still supports the Version 15.5 foundation features: improved OpenAPI documentation, route schemas, client examples, filtering, pagination, sorting, compact finding responses, persistent SQLite job storage, and API key protection:

```powershell
curl http://127.0.0.1:8088/health
curl http://127.0.0.1:8088/version
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/jobs
curl -X POST http://127.0.0.1:8088/scans -H "Content-Type: application/json" -H "X-VulScan-API-Key: change-this-local-dev-key" -d "{\"target\":\"127.0.0.1\",\"scan_mode\":\"safe\",\"json_report\":true,\"html_report\":false,\"save_db\":true}"
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/jobs/JOB_ID
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/scans
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/jobs?status=completed&limit=10"
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/jobs/JOB_ID/findings?priority_label=Fix%20First&compact=true"
curl -H "X-VulScan-API-Key: change-this-local-dev-key" "http://127.0.0.1:8088/exports/findings?format=csv&severity=Medium"
```

The API binds to `127.0.0.1` by default and is for local development only. `GET /health` and `GET /version` are public. OpenAPI docs are available at `http://127.0.0.1:8088/docs` and `http://127.0.0.1:8088/openapi.json`. Client examples are in `examples\api`. When `VULSCAN_API_KEY` is set, scan, job, and export endpoints require `X-VulScan-API-Key: YOUR_KEY` or `Authorization: Bearer YOUR_KEY`. API jobs are stored in SQLite so job history can survive API restarts; queued or running jobs interrupted by restart are marked failed with `API_JOB_INTERRUPTED`. Job, scan, finding, and findings export endpoints support pagination and endpoint-specific filters; finding endpoints also support `compact=true`. Store API keys in the environment, not in code, and do not commit them. Credentialed scans are not exposed through the API, and request models reject passwords, tokens, private keys, API keys, authorization fields, and unexpected fields. See `docs\API.md`.

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

Version 13.9 consolidates passive Web DAST reporting into `web_dast_summary`, `web_dast_sections`, terminal output, JSON, and HTML. It combines scope, politeness, robots, sitemap, crawler, headers, cookies, forms, and passive risk indicators without adding active vulnerability testing. Passive findings are indicators, not proof of exploitability, and written authorisation is still required. Future safe active checks should only be added after scope and report controls remain stable.

Version 14.5 adds local vulnerability intelligence matching with `--vuln-intel`, local CVE-style feed matching with `--use-cve-feed`, local EPSS metadata enrichment with `--use-epss`, and local exploit availability metadata enrichment with `--use-exploit-metadata`. Rules, feeds, EPSS metadata, and exploit availability metadata are loaded only from local files, matched against normalised service/software inventory, and reported as conservative indicators. Version-aware rules and feed affected-version ranges require product/version evidence; unknown versions are treated as insufficient evidence. Version 14.5 does not download CVE feeds, EPSS data, exploit metadata, exploit code, or perform live vulnerability checks.

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
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --robots --sitemap --headers --cookies --forms --passive-summary --max-pages 10 --max-depth 1 --request-delay 1 --show-scope --json --html
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
