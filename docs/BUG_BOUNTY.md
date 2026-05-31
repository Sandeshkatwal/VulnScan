# Bug Bounty Scope And Recon

The Bug Bounty Scope Manager stores local program scope rules for authorised testing workflows. Version 18.1 also adds a safe recon foundation for manually provided targets. It does not add exploitation, exploit execution, exploit downloads, subdomain brute forcing, wordlist enumeration, credential attacks, bypass automation, stealth logic, high-rate requests, or destructive payloads.

Always verify the live program policy before testing.

## Purpose

Bug bounty scope files help VulScan decide whether a target, domain, URL, or IP address is covered by a local program scope file before scanning. Out-of-scope rules override in-scope rules, and unknown targets are out of scope by default.

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

Do not add real private program data unless it is authorised for local storage. Do not store secrets, session cookies, tokens, passwords, private keys, real client data, or sensitive bounty data in scope files.

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

## Recon Foundation

Recon imports known domains, hosts, URLs, or IP addresses from manual input or a local text file, validates them against the selected bug bounty scope, and gently probes HTTP/HTTPS metadata.

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

Open the Bug Bounty section to:

- Review local program cards.
- Inspect in-scope and out-of-scope domains, URLs, API base URLs, and IP ranges.
- Review forbidden actions, allowed test types, disallowed test types, and rate limits.
- Check whether a target is in scope.

Open the Bug Bounty Recon section to paste known targets, select a local scope file, keep scope enforcement enabled, set gentle request limits, and review live metadata and skipped targets.

The recon dashboard does not include brute-force, wordlist, exploit, payload, credential, or scan-launch controls.

## Safety Warning

Always verify the live program policy before testing. Local scope files may be stale, incomplete, or manually entered incorrectly.
