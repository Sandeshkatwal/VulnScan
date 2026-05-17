# Web DAST Engine

Version 13.0 starts VulScan's Web DAST Engine with a safe crawler foundation.

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

## Report Fields

JSON and HTML reports include:

- `web_scan_summary`
- `crawled_pages`
- `discovered_forms`
- `web_findings`
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

These findings are discovery and review indicators. They do not prove a vulnerability by themselves.

## Future Work

Future Web DAST versions can add header checker integration, cookie audit, and safe opt-in checks. Payload-based checks must remain controlled, authorised, and non-destructive.
