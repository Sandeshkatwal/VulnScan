# OWASP A10 Error Handling

VulScan Version 20.4 adds safe A10 Mishandling of Exceptional Conditions checks for authorised web assessment workflows. The module analyses already observed response snippets, status codes, endpoint metadata, and validation results for error-handling indicators, exception exposure evidence, verbose error evidence, framework debug indicators, sensitive error content, and fail-safe review required signals.

## Scope

Implemented checks:

- Python traceback, generic stack trace, Node/Express stack trace, Java exception, PHP warning/notice/fatal error, and exception message indicators.
- Database error indicators, including SQL error strings, driver errors, connection errors, and ORM error indicators.
- Framework debug indicators for Django, Flask/Werkzeug, Laravel/Whoops, Rails, Express, Spring Boot, ASP.NET, Java, PHP, Python, and Node.
- HTTP error pattern analysis from existing observations, including repeated 5xx status clusters and 5xx observations on common endpoints.
- Fail-safe manual review indicators for authentication, password reset, payment/billing, admin, account, file upload, import, and export workflows.
- Sensitive error content indicators such as internal paths, environment names, framework versions, database names, host/cloud metadata strings when already present in observed content.

Evidence strength values are `informational`, `weak_indicator`, `strong_indicator`, and `confirmed_finding`. A10 checks default to indicators and use `manual_validation_required` where workflow context matters.

## Safety Design

VulScan does not perform crash testing, DoS testing, forced failure testing, payload injection, SQL/XSS/SSRF/LFI/RCE payloads, form submission, or state-changing requests for A10 checks. No errors are forced and no payloads are sent.

A10 analysis uses only already available response snippets, status codes, endpoint intelligence, and validation metadata. Missing A10 evidence does not mean error handling is safe; it may mean response snippets were unavailable or no relevant error responses were observed.

## Snippet Redaction

Full response bodies are not stored. Snippets are limited to 1000 characters and redacted before reporting. VulScan redacts tokens, cookies, passwords, API keys, bearer strings, session identifiers, and internal paths where possible while preserving the indicator type needed for review.

## CLI

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --a10-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --a10-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main validate --targets-file data\validation\sample_validation_targets.json --a10-checks --owasp-assess --json --html
```

## API

```http
GET /owasp/a10/rules
POST /owasp/a10/assess
```

Example request:

```json
{
  "target": "http://127.0.0.1:8000",
  "responses": [
    {
      "url": "http://127.0.0.1:8000/error",
      "status_code": 500,
      "body_snippet": "Traceback ...",
      "headers": {}
    }
  ],
  "endpoint_results": []
}
```

The response contains `a10_error_handling_summary` and `a10_error_handling_evidence`. Returned snippets are redacted and bounded.

## Dashboard

The OWASP Assessment screen includes an A10 Error Handling section when the selected result contains A10 data. It shows summary cards, error evidence, status code pattern analysis, framework debug indicators, fail-safe checklist, recommendations, limitations, indicator confidence, and manual validation required notes.

## Remediation Guidance

- Disable detailed errors and framework debug pages in production.
- Return generic user-facing error messages.
- Log diagnostic details safely server-side.
- Avoid exposing stack traces, source paths, framework versions, database details, environment names, or cloud metadata strings.
- Review sensitive workflows for fail-safe behaviour.
- Review repeated 5xx observations as operational and security hardening signals.

## Limitations

A10 checks are observation-based. VulScan does not confirm fail-open behaviour automatically and does not force application errors. Manual validation is required to determine business impact and whether sensitive workflows fail closed.
