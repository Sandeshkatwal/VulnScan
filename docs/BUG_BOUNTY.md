# Bug Intelligence Workflow

The Bug Intelligence workflow stores local program scope rules for authorised security testing and responsible disclosure workflows. It includes a Program Scope Manager, Recon Intelligence, endpoint and parameter discovery, OWASP indicator mapping, and safe active validation. It does not add exploitation, exploit execution, exploit downloads, subdomain brute forcing, wordlist enumeration, credential attacks, bypass automation, stealth logic, high-rate requests, or destructive payloads.

Always verify the live program policy before testing.

This workflow can support bug bounty, internal testing, and responsible disclosure, but VulScan uses broader "Bug Intelligence" wording for the product experience.

## Endpoint and Parameter Discovery

Version 18.2 adds safe endpoint and parameter discovery for the bug intelligence workflow.
It analyses supplied URLs and paths from local files, API requests, or dashboard
input, then normalises, deduplicates, classifies, and scores candidates for
manual review. It does not send network requests, submit forms, run payloads, or
confirm vulnerabilities.

URL input is newline-delimited. Each line can be a full URL, a path-only entry,
a URL with query parameters, or an API endpoint path. Path-only entries can use
`--base-url` or the dashboard Base URL field.

```powershell
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\bug_bounty\endpoints\sample_urls.txt --base-url http://127.0.0.1:8000
```

Scope-aware usage:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\bug_bounty\endpoints\sample_urls.txt --base-url http://127.0.0.1:8000 --bug-bounty-scope data\bug_bounty\sample_program_scope.json --enforce-scope --json --html
```

Parameter intelligence categories include redirect, IDOR, path traversal,
SSRF-like, injection/reflection, debug/config, and sensitive token indicators.
Sensitive parameter values such as `token`, `password`, `api_key`, `session`,
`auth`, `jwt`, and `code` are redacted.

Candidate scoring is heuristic:

- High Interest: `>= 60`
- Medium Interest: `>= 35`
- Low Interest: `>= 15`
- Informational: `< 15`

API example for `POST /bug-bounty/endpoints/analyse`:

```json
{
  "urls": [
    "http://127.0.0.1:8000/account?id=123",
    "http://127.0.0.1:8000/redirect?next=/dashboard"
  ],
  "base_url": "http://127.0.0.1:8000",
  "scope_file": "data/bug_bounty/sample_program_scope.json",
  "enforce_scope": true
}
```

Endpoint reports can be listed from `/bug-bounty/endpoints/reports`.

The dashboard includes **Bug Intelligence -> Endpoints** with multiline URL input,
base URL, scope selection, scope enforcement, summary cards, endpoint
candidates, parameter intelligence, and skipped URL tables.

Safety warning: Parameter candidates are not confirmed vulnerabilities. They
are indicators for authorised manual validation only.

## OWASP Top 10 Indicator Mapping

Version 18.3 can map findings, endpoint candidates, and parameter candidates to
OWASP Top 10:2025 indicator categories with `--owasp-map` or the OWASP
dashboard view.

This helps organise security finding notes and reports by familiar OWASP themes, but
it does not confirm vulnerabilities. A mapped IDOR-style parameter, login
endpoint, debug endpoint, upload endpoint, or missing-header finding remains an
indicator until manually validated within program rules.

Use:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\bug_bounty\endpoints\sample_urls.txt --owasp-map --json --html
```

The report includes mapped items, confidence, mapping reason, manual validation
requirements, coverage gaps, and limitations.

## Safe Active Validation

Version 18.4 adds a safe active validation foundation for authorised in-scope
URLs. It runs limited non-destructive checks and reports potential indicators
only. It does not confirm exploitability.

Supported checks:

- reflected input observation with a harmless marker
- open redirect behaviour indicator using a same-origin path only
- CORS configuration indicator with a harmless Origin header
- directory listing indicator
- default public file observation for `/robots.txt`, `/sitemap.xml`,
  `/.well-known/security.txt`, and `/security.txt`
- HTTP methods indicator using `OPTIONS` only

Blocked checks include SQL injection, XSS payloads, SSRF active probes, path
traversal payloads, command injection, template injection, XXE,
deserialisation, file upload exploitation, authentication bypass, brute force,
password reset exploitation, payment testing, and destructive HTTP methods.

Run:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main validate --targets-file data\bug_bounty\validation\sample_validation_targets.json
```

Scope-aware:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main validate --targets-file data\bug_bounty\validation\sample_validation_targets.json --bug-bounty-scope data\bug_bounty\sample_program_scope.json --enforce-scope --json --html
```

API endpoint:

```text
POST /bug-bounty/validate
```

Dashboard usage is available in **Bug Intelligence -> Safe Validation**. The view has
a safety notice, target input, allowed check selector, scope selector, low-rate
controls, result table, skipped targets, and evidence summaries.

Every result should be treated as: Indicator only. Manual validation required.
No exploitability confirmed.

## Submission and Retest Tracking

Version 18.6 adds local Submission and Retest Tracking for Security Finding Reports. It tracks status, duplicate or accepted outcomes, bounty/payment notes, follow-up dates, evidence references, timeline events, and retest status.

This is workflow tracking only. VulScan does not automatically submit reports to external platforms, does not integrate platform API tokens, and does not store platform credentials. Retest tracking is manual/status-based unless the user explicitly runs existing Safe Validation and links that evidence.

```powershell
.\.venv311\Scripts\python.exe -m scanner.main submission create --report-id REPORT_ID --program-name "Demo Program" --platform "manual" --status draft
.\.venv311\Scripts\python.exe -m scanner.main retest create --submission-id SUBMISSION_ID --status retest_required --note "Retest requested."
```

## Purpose

Program scope files help VulScan decide whether a target, domain, URL, or IP address is covered by a local program scope file before scanning. Out-of-scope rules override in-scope rules, and unknown targets are out of scope by default.

Scope decisions are local decision support. They do not replace the official program policy.

## Scope File Location

Local scope JSON files live under:

```text
data/bug_bounty/
```

The included sample is fake demo data only:

```text
data/bug_bounty/sample_program_scope.json
```

Do not add real private program data unless it is authorised for local storage. Do not store secrets, session cookies, tokens, passwords, private keys, real client data, or sensitive disclosure data in scope files.

## Scope File Format

Scope files include:

- `program_id`
- `program_name`
- `platform`
- `policy_url`
- `scope_version`
- `last_updated`
- `safe_testing_notice`
- `in_scope.domains`
- `in_scope.urls`
- `in_scope.api_base_urls`
- `in_scope.ip_ranges`
- `out_of_scope.domains`
- `out_of_scope.urls`
- `out_of_scope.ip_ranges`
- `forbidden_actions`
- `rate_limits`
- `allowed_test_types`
- `disallowed_test_types`
- `notes`

Wildcard domains such as `*.example.com` match subdomains only. They do not match the root domain unless the root domain is also listed explicitly.

## Examples

In-scope examples:

```json
"domains": ["demo-web.local", "*.demo-web.local", "127.0.0.1"]
```

Out-of-scope examples:

```json
"domains": ["payments.demo-web.local"],
"urls": ["https://demo-web.local/logout"]
```

Forbidden actions can include:

```json
["denial_of_service", "brute_force", "credential_stuffing", "data_destruction"]
```

Rate limits can include:

```json
{
  "max_requests_per_minute": 30,
  "request_delay_seconds": 1.0,
  "max_pages": 50,
  "max_depth": 2
}
```

## Scope Enforcement

Load scope without blocking:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --bug-bounty-scope data\bug_bounty\sample_program_scope.json
```

Enforce scope and refuse out-of-scope targets:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --bug-bounty-scope data\bug_bounty\sample_program_scope.json --enforce-scope
```

Scope-aware passive Web DAST:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --bug-bounty-scope data\bug_bounty\sample_program_scope.json --enforce-scope --crawl --headers --cookies --forms --passive-summary --json --html
```

If `--enforce-scope` is set and the target is out of scope, VulScan stops safely before scanning or crawling.

## Recon Intelligence

Recon Intelligence imports known domains, hosts, URLs, or IP addresses from manual input or a local text file, validates them against the selected program scope, and gently probes HTTP/HTTPS metadata.

It does not discover new subdomains, brute-force names, use wordlists, query search engines, call third-party APIs, submit forms, authenticate, fuzz, or send payloads.

Targets file format:

```text
127.0.0.1
http://127.0.0.1:8000/
demo-web.local
https://demo-web.local/
api.demo-web.local
```

Sample file:

```text
data/bug_bounty/recon/sample_targets.txt
```

Run recon from a local file:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main recon --targets-file data\bug_bounty\recon\sample_targets.txt
```

Run scope-aware recon and save JSON/HTML reports:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main recon --targets-file data\bug_bounty\recon\sample_targets.txt --bug-bounty-scope data\bug_bounty\sample_program_scope.json --enforce-scope --json --html
```

Recon collects status code, final URL, redirect chain, response time, page title, selected headers, content type, content length, basic technology hints, and security header presence. It caps response reads, stores metadata only, and does not store full response bodies, cookies, tokens, passwords, session data, or private keys.

Scope rules are applied before probing. Out-of-scope targets are skipped and recorded in the recon summary.

## API Examples

List local scope files:

```powershell
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/bug-bounty/scopes
```

Get one scope by program ID:

```powershell
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/bug-bounty/scopes/demo-bug-bounty-program
```

Check a target:

```powershell
curl -X POST http://127.0.0.1:8088/bug-bounty/scope-check -H "Content-Type: application/json" -H "X-VulScan-API-Key: change-this-local-dev-key" -d "{\"target\":\"https://demo-web.local/\",\"scope_file\":\"data/bug_bounty/sample_program_scope.json\"}"
```

API endpoints only read local JSON files under `data/bug_bounty` and use API key protection when configured.

Run synchronous recon from provided targets:

```powershell
curl -X POST http://127.0.0.1:8088/bug-bounty/recon -H "Content-Type: application/json" -H "X-VulScan-API-Key: change-this-local-dev-key" -d "{\"targets\":[\"http://127.0.0.1:8000/\",\"demo-web.local\"],\"scope_file\":\"data/bug_bounty/sample_program_scope.json\",\"enforce_scope\":true,\"request_delay\":1.0,\"max_requests_per_minute\":30,\"timeout\":5}"
```

List saved recon reports:

```powershell
curl -H "X-VulScan-API-Key: change-this-local-dev-key" http://127.0.0.1:8088/bug-bounty/recon/results
```

## Dashboard Usage

Open the Program Scope section to:

- Review local program cards.
- Inspect in-scope and out-of-scope domains, URLs, API base URLs, and IP ranges.
- Review forbidden actions, allowed test types, disallowed test types, and rate limits.
- Check whether a target is in scope.

Open the Recon section to paste known targets, select a local scope file, keep scope enforcement enabled, set gentle request limits, and review live metadata and skipped targets.

The recon dashboard does not include brute-force, wordlist, exploit, payload, credential, or scan-launch controls.

## Safety Warning

Always verify the live program policy before testing. Local scope files may be stale, incomplete, or manually entered incorrectly.
