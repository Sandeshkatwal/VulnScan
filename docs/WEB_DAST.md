# Web DAST Engine

Version 13.0 starts VulScan's Web DAST Engine with a safe crawler foundation.

Version 13.1 adds passive security header checks to the same `web-scan` workflow.

Version 13.2 improves cookie auditing with value-free Set-Cookie parsing.

Version 13.3 improves passive form discovery and reporting.

Version 13.4 adds a passive web risk summary that consolidates crawler, header, cookie, and form indicators.

Version 13.5 adds web scope and allowlist controls for crawler and passive checks.

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

These findings are discovery and review indicators. They do not prove a vulnerability by themselves.

## Passive Risk Summary

Version 13.4 `web_passive_summary` combines available crawler, header, cookie, and form data into one overview with pages crawled, page errors, forms, login forms, upload forms, observed cookies, cookie issues, missing security headers, disclosure headers, external links, external form actions, grouped indicators by severity, highest web risk, passive risk rating, recommended next steps, and limitations.

The rating is High when any high web finding exists, Medium when no high exists but a medium finding exists, Low when only low findings exist, Informational when only informational findings exist, and None when there are no web findings. The summary helps plan authorised deeper testing but does not submit forms, authenticate, test SQL injection, test XSS, send payloads, fuzz, or prove exploitability.

## Scope Controls

Version 13.5 keeps the start URL host in scope by default and skips external domains unless explicitly authorised. `--same-host-only` is true by default. Use `--allow-host` to add specific authorised hosts, `--deny-host` to block specific hosts, `--allow-path` to limit crawling and passive checks to path prefixes, and `--deny-path` to block path prefixes such as logout or destructive administrative routes. Use `--include-subdomains` only when subdomains of the start domain are in scope.

Scope decisions are recorded in `web_scope_summary`, including counts for external hosts, denied hosts, denied paths, paths outside allow rules, static files, unsupported schemes, duplicates, depth limits, and page limits. Up to 100 skipped URL samples are stored for review. Scope controls are required before any future active testing and must reflect explicit authorisation.

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
