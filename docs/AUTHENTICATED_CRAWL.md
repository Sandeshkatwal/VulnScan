# Authenticated Crawl

VulScan 21.1 adds Authenticated Crawl for authorised web assessment workflows. It uses a local Session Profile to provide Authentication Context, applies Session Boundary Controls before each request, and stores Redacted Authenticated Evidence only.

## Safety Model

Authenticated Crawl is GET-only in 21.1. It does not submit forms, click buttons, run JavaScript actions, call logout endpoints, or follow links that look destructive. Auth Boundary Enforcement checks the Session Profile allowed hosts, allowed paths, blocked paths, default destructive path blocklist, same-origin policy, max depth, and max pages before a URL is requested.

Default blocked path keywords include logout, signout, delete, remove, destroy, deactivate, close-account, payment, checkout, transfer, purchase, subscribe, unsubscribe, admin/delete, account/delete, reset-password/confirm, and password/change.

## Redaction Model

Authentication headers and cookies may be used in memory for the request. VulScan does not print or report raw Authorization headers, Cookie headers, bearer tokens, passwords, or session cookie values. Reports include auth type, cookie/header names, role label, boundary decisions, status codes, page titles, and safe summaries.

## Session Expiry Indicator

VulScan records a Session Expiry Indicator when it observes signals such as HTTP 401/403, redirect/final URL pointing to login or sign-in, login page title, login-required snippet indicators, or Set-Cookie clearing behavior. This is classification only. Manual Validation Required.

## CLI

```powershell
.\.venv311\Scripts\python.exe -m scanner.main authenticated-crawl --url http://127.0.0.1:8000/dashboard --auth-profile data\auth_profiles\sample_session_profile.redacted.json --max-pages 30 --max-depth 2 --request-delay 1.0 --json --html

.\.venv311\Scripts\python.exe -m scanner.main authenticated-crawl --url http://127.0.0.1:8000/dashboard --auth-profile data\auth_profiles\sample_session_profile.redacted.json --dry-run --json --html
```

## API

`POST /authenticated/crawl` runs a bounded Authenticated Crawl. API key protection applies.

```json
{
  "url": "http://127.0.0.1:8000/dashboard",
  "profile": {},
  "max_pages": 30,
  "max_depth": 2,
  "request_delay": 1.0,
  "timeout": 5,
  "same_origin_only": true,
  "dry_run": false
}
```

## Dashboard

The Authenticated Assessment dashboard includes Authenticated Crawl configuration, redacted profile summary, crawl summary, results table, boundary events, and Redacted Authenticated Evidence notes. The UI does not display raw auth headers, cookies, tokens, or passwords.

## Limitations

Version 21.1 does not perform role comparison, session expiry duration testing, form submission, authenticated state-changing workflows, JavaScript-driven crawling, or automated business-logic validation. Future work can add explicit user-approved authenticated request workflows and richer Authenticated Scope reporting.
## Version 21.2 Role Endpoint Map

Authenticated Crawl now includes a role endpoint map using the Session Profile role label, discovered endpoints, inferred actions, and Manual Validation Required needs. VulScan does not compare different roles automatically. See `docs/ROLE_PERMISSION_MAPPING.md`.
