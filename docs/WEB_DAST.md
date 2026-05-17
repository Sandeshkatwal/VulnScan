# Web DAST Engine

Version 13.0 starts VulScan's Web DAST Engine with a safe crawler foundation.

Version 13.1 adds passive security header checks to the same `web-scan` workflow.

Version 13.2 improves cookie auditing with value-free Set-Cookie parsing.

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

## What It Does Not Do

Version 13.0 does not:

- Submit forms.
- Authenticate.
- Bypass access controls.
- Crawl external domains by default.
- Fuzz parameters.
- Test SQL injection.
- Test XSS.
- Send attack payloads.
- Perform exploitation or destructive checks.

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

These findings are discovery and review indicators. They do not prove a vulnerability by themselves.

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

## Future Work

Future Web DAST versions can add header checker integration, cookie audit, and safe opt-in checks. Payload-based checks must remain controlled, authorised, and non-destructive.
