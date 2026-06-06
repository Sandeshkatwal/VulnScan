# OWASP A05 Injection

VulScan 20.5 adds A05 Injection candidate and reflection analysis for authorised web assessment work.

## Scope

The A05 module identifies injection candidates and input handling indicators from existing endpoint discovery, parameter intelligence, form discovery, and optional harmless marker reflection observations. It uses OWASP Top 10:2025 A05 Injection as the category model.

## Checks Implemented

- Parameter intelligence for query, search, comment, message, filter, sort, callback, path, file, template, and API-style parameters.
- Form input candidate analysis for text inputs, search inputs, email inputs, textareas, comment/feedback forms, and hidden field names only.
- API input candidate analysis for `/api/`, `/v1/`, `/v2/`, `/graphql`, REST object paths, and filter/sort query patterns.
- Optional safe reflection analysis for selected GET parameters.
- Reflection context hints: `html_text`, `attribute_like`, `script_like`, `json_like`, `url_like`, and `unknown`.

## Safe Reflection Analysis

Safe reflection uses a marker beginning with `VULSCAN_SAFE_MARKER_` and a short random alphanumeric suffix. The marker contains only letters, numbers, and underscores.

The module replaces only the selected GET query parameter value, performs at most one request per selected parameter, honours the configured request delay, reads at most 256 KB of response data, stores only a redacted snippet around the marker, and does not store full response bodies.

## What Is Not Checked

VulScan 20.5 does not add exploitation, exploit execution, form submission, schema fuzzing, GraphQL introspection, POST/PUT requests, brute force, SSRF probing, payload spraying, or bypass checks.

No SQL injection, XSS, command injection, template injection, LDAP injection, or NoSQL injection payloads are used.

## Candidate vs Confirmed

A parameter name, form input, API pattern, or reflected harmless marker is an indicator only. It is not a confirmed injection finding. Manual validation is required before reporting impact.

`confirmed_finding` is reserved for externally supplied manually confirmed evidence.

## CLI Examples

```powershell
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --a05-checks --owasp-assess --json --html
```

```powershell
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --a05-checks --safe-reflection --max-reflection-checks 10 --owasp-assess --json --html
```

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --a05-checks --owasp-assess --json --html
```

## API Examples

`GET /owasp/a05/rules` returns the local A05 rule groups.

`POST /owasp/a05/assess` builds A05 evidence from supplied endpoint, parameter, and form metadata:

```json
{
  "target": "http://127.0.0.1:8000",
  "endpoint_results": [],
  "parameter_results": [],
  "forms": [],
  "safe_reflection": false
}
```

## Dashboard Usage

The OWASP Assessment dashboard shows A05 Injection summary cards, parameter candidates, reflection evidence, form input candidates, API input candidates, manual validation checklist, recommendations, and limitations.

Dashboard wording uses candidate, indicator, evidence, confidence, manual validation required, harmless marker only, no payloads were used, and no exploitability confirmed.

## Remediation Guidance

Review output encoding, server-side input validation, parameterised queries, template rendering context, API filter/sort handling, and command/path/template-like parameters. Confirm impact manually before reporting.
