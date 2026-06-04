# OWASP A07 Authentication Failures

VulScan Version 20.3 adds safe A07 Authentication Failures checks for authorised web assessment workflows. The module collects authentication indicators, session management indicators, login workflow evidence, password reset workflow evidence, cookie/session evidence, rate-limit header indicators, protocol surface indicators, and manual validation needs.

## Scope

Implemented checks:

- Authentication endpoint discovery from existing URLs and endpoint discovery results.
- Login, sign-in, authentication callback, logout, registration, password reset, MFA/2FA, OAuth/OIDC, and SAML surface indicators.
- Session-like cookie names and recommended attributes: Secure, HttpOnly, SameSite, SameSite=None with Secure, and persistence indicators.
- Auth form indicators from safe form discovery: password fields, CSRF-like field names, remember-me checkbox names, action scheme, and password reset forms.
- Password reset and token URL indicators using parameter names only.
- Rate-limit header indicators from supplied response metadata.

Evidence strength values are `informational`, `weak_indicator`, `strong_indicator`, and `confirmed_finding`. A07 checks default to indicators. Manual validation required is included where context matters.

## Safety Design

VulScan does not submit login forms, create accounts, reset passwords, perform login attempts, perform brute force, perform credential stuffing, perform password guessing, test MFA bypass, automate authentication bypass, or perform repeated requests to test rate limits.

Cookie values, hidden field values, secrets, tokens, passwords, private keys, and full sensitive response bodies are not stored. URL token values are redacted; only parameter names are retained.

## CLI

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --a07-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --a07-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main validate --targets-file data\validation\sample_validation_targets.json --a07-checks --owasp-assess --json --html
```

## API

```http
GET /owasp/a07/rules
POST /owasp/a07/assess
```

Example request:

```json
{
  "target": "https://127.0.0.1:8000",
  "urls": [],
  "headers": {},
  "set_cookie_headers": [],
  "forms": [],
  "endpoint_results": [],
  "parameter_results": []
}
```

The response contains `a07_authentication_summary` and `a07_authentication_evidence`.

## Dashboard

The OWASP Assessment screen includes an A07 Authentication Failures section when the selected result contains A07 data. It shows summary cards, authentication endpoint evidence, session cookie evidence, auth form indicators, rate-limit header indicators, recommendations, limitations, indicator confidence, and a manual validation checklist.

## Remediation Guidance

- Review login controls manually.
- Review password reset token handling, expiration, single-use behaviour, and rate limiting.
- Configure Secure, HttpOnly, and SameSite cookie attributes according to cookie purpose.
- Review remember-me behaviour and persistent session handling.
- Review MFA/2FA if present.
- Review account lockout and rate limiting manually.
- Avoid exposing sensitive tokens in URLs where possible.
- Review logout and session invalidation manually.

## Limitations

A07 evidence is based on available metadata and may require manual validation. Missing evidence does not mean authentication is secure; it may mean the workflow was not assessed, was not reachable, or requires authenticated/manual review.
