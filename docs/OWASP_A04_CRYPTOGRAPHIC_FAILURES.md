# OWASP A04 Cryptographic Failures

VulScan Version 20.2 adds a safe A04 Cryptographic Failures module for authorised web assessment workflows. The module collects transport security indicators, cookie security evidence, sensitive data over cleartext indicators, mixed content indicators, HSTS evidence, and TLS metadata.

## Scope

Implemented checks:

- HTTP URLs and sensitive-looking HTTP paths or parameter names.
- Cleartext form submission indicators from discovered form metadata.
- HSTS presence, max-age, includeSubDomains, and preload indicators on HTTPS responses.
- Cookie Secure, HttpOnly, SameSite, SameSite=None without Secure, and session-like cookie attribute indicators.
- Mixed content indicators from limited HTML snippets or crawler metadata.
- TLS certificate metadata: subject common name, issuer common name, validity dates, days until expiry, expired state, hostname match, and self-signed indicator.

Evidence strength values are `informational`, `weak_indicator`, `strong_indicator`, and `confirmed_finding`. A04 checks default to indicators. Manual validation required is included where context matters.

## Safe Design

VulScan does not submit forms, fetch external mixed-content assets, intercept traffic, capture credentials, store cookie values, store secrets, store tokens, store passwords, store private keys, or store full sensitive response bodies.

TLS metadata uses a normal certificate handshake only. Version 20.2 does not test weak ciphers, perform protocol downgrade testing, perform TLS attack automation, or run exploit checks.

Cookie values are redacted. Reports store cookie names and attributes only.

## CLI

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --a04-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --a04-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main validate --targets-file data\validation\sample_validation_targets.json --a04-checks --owasp-assess --json --html
```

## API

```http
GET /owasp/a04/rules
POST /owasp/a04/assess
```

Example request:

```json
{
  "target": "https://127.0.0.1:8000",
  "headers": {},
  "set_cookie_headers": [],
  "urls": [],
  "forms": [],
  "html_snippet": ""
}
```

The response contains `a04_crypto_summary` and `a04_crypto_evidence`.

## Dashboard

The OWASP Assessment screen includes an A04 Cryptographic Failures section when the selected result contains A04 data. It shows summary cards, transport evidence, cookie evidence, TLS metadata, mixed content indicators, recommendations, limitations, indicator confidence, and manual validation notes.

## Remediation Guidance

- Enforce HTTPS and redirect HTTP to HTTPS.
- Configure HSTS after confirming HTTPS readiness.
- Set Secure, HttpOnly, and SameSite cookie attributes according to cookie purpose.
- Avoid sensitive data over HTTP and avoid sensitive values in URLs.
- Remove mixed content indicators by loading resources over HTTPS.
- Monitor TLS certificate expiry and hostname coverage.

## Limitations

A04 evidence is based on available metadata and may require manual validation. Missing evidence does not mean a workflow is secure; it may mean the workflow was not assessed, was not reachable, or requires authenticated/manual review.
