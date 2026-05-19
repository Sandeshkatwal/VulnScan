# Web DAST Engine

Version 13.0 starts VulScan's Web DAST Engine with a safe crawler foundation.

Version 13.1 adds passive security header checks to the same `web-scan` workflow.

Version 13.2 improves cookie auditing with value-free Set-Cookie parsing.

Version 13.3 improves passive form discovery and reporting.

Version 13.4 adds a passive web risk summary that consolidates crawler, header, cookie, and form indicators.

Version 13.5 adds web scope and allowlist controls for crawler and passive checks.

Version 13.6 adds rate limiting, retry limits, backoff, Retry-After handling, and max-error politeness controls.

Version 13.7 adds robots.txt awareness for fetching, reporting, and optionally respecting crawl guidance.

Version 13.8 adds passive sitemap discovery and optional sitemap-assisted crawling within configured scope.

Version 13.9 consolidates passive Web DAST reporting across scope, politeness, robots, sitemap, crawler, headers, cookies, forms, and passive risk indicators.

Use it only on web applications you own or have explicit permission to assess.

## What It Does

- Sends bounded `GET` requests only.
- Crawls the same host by default.
- Respects `--max-pages`, `--max-depth`, and `--timeout`.
- Normalises URLs and avoids duplicate requests.
- Ignores fragments.
- Skips unsafe schemes such as `mailto:`, `tel:`, `javascript:`, `data:`, and `file:`.
- Skips common static and binary assets such as images, archives, media files, fonts, CSS, and JavaScript files.
- Discovers links and forms.
- Records password fields and file-upload fields as review indicators.
- Writes JSON and HTML report sections for crawl summary, pages, forms, and web findings.
- Optionally checks passive security header indicators with `--headers`.
- Optionally checks cookie attributes with `--cookies`.
- Stores cookie names and attributes only, never cookie values.
- Optionally maps and classifies forms with `--forms` without submitting them.
- Stores input names and types only, never input values or hidden values.
- Optionally builds a consolidated passive risk overview with `--passive-summary`.
- Applies explicit scope controls for allowed hosts, denied hosts, allowed paths, denied paths, and subdomain inclusion.
- Applies request pacing and request-per-minute limits to Web DAST HTTP requests.
- Reuses fetched page data for header, cookie, form, and passive summary analysis.
- Optionally fetches and reports robots.txt guidance with `--robots`.
- Optionally discovers, parses, and reports XML sitemaps with `--sitemap`.
- Builds a consolidated `web_dast_summary` and `web_dast_sections` report view for passive Web DAST output.

## What It Does Not Do

Current Web DAST passive checks do not:

- Submit forms.
- Authenticate.
- Bypass access controls.
- Crawl external domains by default.
- Fuzz parameters.
- Test SQL injection.
- Test XSS.
- Send attack payloads.
- Perform exploitation or destructive checks.
- Prove exploitability from passive indicators.
- Treat robots.txt as authorisation to scan.
- Treat sitemap discovery as authorisation to scan.
- Bypass scope, robots, rate limits, max pages, or max depth when using sitemap URLs.
- Add active vulnerability testing through the consolidated report view.

## Commands

Basic crawler run:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://example.com --crawl
```

Limit crawl depth and page count, and write reports:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://example.com --crawl --max-pages 10 --max-depth 1 --json --html
```

Disable link-following and fetch only the start URL:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://example.com --no-crawl
```

Run passive header checks against crawled pages:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --headers
```

Run passive header checks against only the start URL:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --no-crawl --headers
```

Run focused cookie attribute checks against only the start URL:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --cookies
```

Run cookie checks across crawled same-host pages:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --cookies --max-pages 10 --max-depth 1 --json --html
```

Run enhanced form discovery against only the start URL:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --forms
```

Run enhanced form discovery across crawled same-host pages:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --forms --max-pages 10 --max-depth 1 --json --html
```

Run the Version 13.4 passive summary against only the start URL:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --passive-summary
```

Run all passive web modules and include the consolidated summary:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --headers --cookies --forms --passive-summary --max-pages 10 --max-depth 1 --json --html
```

When `--passive-summary` is used alone, VulScan fetches the start URL, checks headers and cookies from that response, and performs basic form discovery on that page only. It does not crawl beyond the start URL unless `--crawl` is explicitly provided.

Show effective scope before crawling:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --show-scope
```

Allow an additional authorised host:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --allow-host www.example.com --max-pages 10
```

Restrict crawling and passive checks to authorised path prefixes while denying sensitive paths:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --allow-path /docs --deny-path /logout --headers --cookies --forms --passive-summary --json --html
```

Use Version 13.6 politeness controls:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --request-delay 1
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --max-requests-per-minute 30 --retry-limit 1 --max-errors 5
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --headers --cookies --forms --passive-summary --max-pages 10 --max-depth 1 --request-delay 1 --json --html
```

Use Version 13.7 robots.txt awareness:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --robots
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --robots --respect-robots --max-pages 10 --max-depth 1
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --robots --no-respect-robots --headers --cookies --forms --passive-summary --json --html
```

Use Version 13.8 sitemap discovery:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --sitemap
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --robots --sitemap
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --sitemap --sitemap-url https://example.com/sitemap.xml
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --sitemap --use-sitemap-for-crawl --max-pages 20 --max-depth 1 --json --html
```

Recommended full passive report command:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url https://example.com --crawl --robots --sitemap --headers --cookies --forms --passive-summary --max-pages 10 --max-depth 1 --request-delay 1 --show-scope --json --html
```

## Report Fields

JSON and HTML reports include:

- `web_scan_summary`
- `crawled_pages`
- `discovered_forms`
- `web_findings`
- `web_header_summary` when `--headers` is used
- `web_header_results` when `--headers` is used
- `web_cookie_summary` when `--headers` or `--cookies` is used
- `web_cookie_results` when `--headers` or `--cookies` is used
- `web_form_summary` when `--forms` is used
- `web_form_results` when `--forms` is used
- `web_passive_summary` when `--passive-summary` is used
- `web_scope_summary`
- `skipped_url_samples`
- `web_politeness_summary`
- `request_error_samples`
- `web_robots_summary` when `--robots` is used
- `web_sitemap_summary`, `web_sitemap_results`, and `web_sitemap_url_samples` when `--sitemap` is used
- `web_dast_summary` and `web_dast_sections` for the consolidated passive Web DAST report
- top-level `findings`

Each page result includes URL, method, status code, content type, title, depth, response time, link count, form count, internal links, external links, and forms.

Each form result includes page URL, method, action, input names, input types, password-field status, and file-upload status.

## Findings

The crawler emits standard VulScan findings for:

- Web crawl completion.
- Password form discovery.
- File-upload form discovery.
- External links discovered but not crawled.
- Crawl errors.

With `--headers`, VulScan also emits deduplicated findings for:

- Missing `Strict-Transport-Security` on HTTPS responses.
- Missing `Content-Security-Policy`.
- Missing `X-Frame-Options`.
- Missing `X-Content-Type-Options`.
- Missing `Referrer-Policy`.
- Missing `Permissions-Policy`.
- `Server` header disclosure.
- `X-Powered-By` header disclosure.
- Cookies missing Secure, HttpOnly, or SameSite flags.

With `--cookies`, VulScan emits duplicate-safe cookie findings for:

- Cookie missing Secure.
- Cookie missing HttpOnly.
- Cookie missing SameSite.
- SameSite=None without Secure.
- Persistent cookie missing one or more recommended security flags.
- Cookie audit completed.

With `--forms`, VulScan emits passive form findings for:

- Login form discovered.
- Login form served over HTTP.
- HTTPS page form submits to HTTP.
- File upload form discovered.
- Form missing CSRF token indicator.
- Sensitive-looking hidden field names.
- External form action discovered.
- Web form discovery completed.

With `--passive-summary`, VulScan emits a standard informational finding for summary completion and, when medium or high passive indicators exist, a single review recommendation finding. It does not duplicate every underlying web finding.

With Version 13.5 scope controls, VulScan emits concise scope findings for scope application, external URLs skipped by default, and URLs skipped by deny rules. It does not emit one finding per skipped URL.

With Version 13.6 politeness controls, VulScan emits concise findings for applied rate limits, maximum-error stops, and observed Retry-After handling. It does not emit one finding per request.

With Version 13.7 robots awareness, VulScan emits concise findings for robots.txt reviewed, not found, URLs skipped due to robots.txt, sitemap references, and rules not enforced when `--no-respect-robots` is used. It does not treat robots.txt as a vulnerability source.

With Version 13.8 sitemap discovery, VulScan emits concise findings for discovery completion, out-of-scope sitemap URLs, failed sitemap fetch or parse events, and sitemap URLs added to the crawl queue when `--use-sitemap-for-crawl` is enabled. It does not emit one finding per sitemap URL.

These findings are discovery and review indicators. They do not prove a vulnerability by themselves.

## Passive Risk Summary

Version 13.4 `web_passive_summary` combines available crawler, header, cookie, and form data into one overview with pages crawled, page errors, forms, login forms, upload forms, observed cookies, cookie issues, missing security headers, disclosure headers, external links, external form actions, grouped indicators by severity, highest web risk, passive risk rating, recommended next steps, and limitations.

The rating is High when any high web finding exists, Medium when no high exists but a medium finding exists, Low when only low findings exist, Informational when only informational findings exist, and None when there are no web findings. The summary helps plan authorised deeper testing but does not submit forms, authenticate, test SQL injection, test XSS, send payloads, fuzz, or prove exploitability.

## Scope Controls

Version 13.5 keeps the start URL host in scope by default and skips external domains unless explicitly authorised. `--same-host-only` is true by default. Use `--allow-host` to add specific authorised hosts, `--deny-host` to block specific hosts, `--allow-path` to limit crawling and passive checks to path prefixes, and `--deny-path` to block path prefixes such as logout or destructive administrative routes. Use `--include-subdomains` only when subdomains of the start domain are in scope.

Scope decisions are recorded in `web_scope_summary`, including counts for external hosts, denied hosts, denied paths, paths outside allow rules, static files, unsupported schemes, duplicates, depth limits, and page limits. Up to 100 skipped URL samples are stored for review. Scope controls are required before any future active testing and must reflect explicit authorisation.

## Rate Limiting And Politeness

Version 13.6 defaults to a 0.5 second delay between Web DAST HTTP requests and a maximum of 60 requests per minute. Use `--request-delay` and `--max-requests-per-minute` to tune request volume according to written permission and target capacity. `--retry-limit` controls bounded safe GET retries, `--retry-backoff` controls retry delay, and `--max-errors` stops crawling when too many request errors occur.

`--respect-retry-after` is enabled by default. When a target returns `Retry-After` with a retryable response such as HTTP 429 or 503, VulScan waits up to a safe cap before retrying. Politeness runtime data is recorded in `web_politeness_summary`, and up to 20 request error samples are included as `request_error_samples`. This remains passive scanning only.

## Robots.txt Awareness

Version 13.7 fetches `robots.txt` once from the start URL origin when `--robots` is used. `--respect-robots` is the default in that mode, so URLs disallowed for the configured robots user-agent or wildcard user-agent are not crawled. Use `--no-respect-robots` only when written authorisation explicitly permits ignoring robots guidance.

The robots summary records fetch status, HTTP status, user-agents seen, allow/disallow counts, crawl-delay, sitemap URLs, samples, and the number of URLs skipped by robots.txt. robots.txt is advisory, not authorisation, and sitemap URLs must still remain within configured scope and written permission. No active vulnerability testing is added in Version 13.7.

## Sitemap Discovery

Version 13.8 discovers sitemap URLs from robots.txt `Sitemap` lines, common same-origin paths such as `/sitemap.xml`, `/sitemap_index.xml`, and `/sitemap-index.xml`, and repeated `--sitemap-url` values. Sitemap files are fetched through the existing safe request wrapper and rate limiter, parsed with the Python standard library XML parser, and bounded by `--max-sitemap-urls` and `--max-sitemap-depth`.

Sitemaps are passive discovery sources and do not grant authorisation. Every sitemap file and URL entry is filtered through scope rules; robots rules are also respected when `--robots --respect-robots` is enabled. Sitemap-assisted crawling is off by default. `--use-sitemap-for-crawl` must be explicitly enabled, and even then in-scope sitemap URLs still respect max pages, max depth, scope, robots, static-file skips, duplicate handling, and rate limits. No active vulnerability testing is added in Version 13.8.

## Passive Report Consolidation

Version 13.9 adds `scanner.web_report_summary` and consolidates passive Web DAST output into `web_dast_summary`, `web_dast_sections`, terminal output, JSON reports, and HTML reports. The consolidated report combines scope, politeness, robots, sitemap, crawler, headers, cookies, forms, and passive risk data while keeping the older module-specific report keys for compatibility.

The consolidated report does not add active vulnerability testing. Passive findings are indicators for authorised review, not proof of exploitability. Written authorisation is still required, and VulScan still does not submit forms, authenticate, fuzz, test SQL injection, test XSS, send payloads, or crawl external domains by default.

Future Web DAST versions can add safe active checks only after scope and report controls remain stable.

## Cookie Value Handling

VulScan does not store or print cookie values. Cookie results include only:

- name
- domain
- path
- Secure flag
- HttpOnly flag
- SameSite value
- Expires or Max-Age presence
- session-cookie indicator
- source URL
- HTTPS context
- issue list

If a cookie value is accidentally introduced into evidence, report redaction still removes credential-like strings before JSON and HTML are written.

## Form Value Handling

VulScan does not submit forms and does not store input values. Enhanced form results include only form metadata such as method, action, resolved action URL, classification, counts, input names, input types, CSRF-like field names, and sensitive-looking field-name indicators. Hidden values, token values, and user-provided values are never stored.

## Future Work

Future Web DAST versions can add header checker integration, cookie audit, and safe opt-in checks. Payload-based checks must remain controlled, authorised, and non-destructive.
