# OWASP Assessment Engine

VulScan Version 20.0 adds the OWASP Assessment Engine foundation for authorised web application assessment workflows. It builds OWASP Top 10:2025 category-level results from existing VulScan evidence, endpoint intelligence, parameter intelligence, passive web findings, safe validation results, vulnerability intelligence, and manual notes.

Version 20.9 adds a unified OWASP Assessment report model and Markdown export. The report includes executive summary, A01-A10 coverage matrix, evidence strength summary, manual validation checklist, developer remediation guidance, coverage gaps, limitations, and safe testing statement. See `docs/OWASP_ASSESSMENT_REPORTING.md`.

Version 21.0 adds Authenticated Web Assessment context support. Redacted Session Profile metadata can improve A01/A07 evidence context and Auth-Required Endpoint classification. Manual validation remains required for access-control and authentication conclusions.

The engine does not exploit, brute force, bypass authentication, submit destructive payloads, or scan out-of-scope assets. Results are evidence and coverage oriented.

## OWASP Top 10:2025 Categories

- A01:2025 Broken Access Control
- A02:2025 Security Misconfiguration
- A03:2025 Software Supply Chain Failures
- A04:2025 Cryptographic Failures
- A05:2025 Injection
- A06:2025 Insecure Design
- A07:2025 Authentication Failures
- A08:2025 Software or Data Integrity Failures
- A09:2025 Security Logging & Alerting Failures
- A10:2025 Mishandling of Exceptional Conditions

## Evidence Model

OWASP Evidence records include source, affected URL, affected parameter, observed signal, OWASP category, confidence, evidence strength, assessment status, manual-validation flag, recommendation theme, limitation, and timestamp.

Confidence levels are Low, Medium, and High.

Evidence strength levels are `weak_indicator`, `strong_indicator`, `confirmed_finding`, `informational`, and `not_assessed`.

Assessment statuses are `detected_indicator`, `needs_manual_validation`, `confirmed`, `not_detected`, `not_assessed`, and `coverage_gap`.

`confirmed_finding` and `confirmed` are used only when supplied evidence already supports that status. Parameter-name indicators alone are never confirmed findings.

## Coverage

Coverage statuses are `assessed`, `partially_assessed`, `not_assessed`, `manual_only`, and `coverage_gap`.

No indicator found does not mean the category is secure. It may mean the category was not assessed or requires authenticated/manual testing.

The assessment quality score is a 0-100 coverage and evidence-quality score, not an application security rating. Labels are `Limited`, `Developing`, `Good Coverage`, and `Strong Coverage`.

## CLI

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --vuln-intel --prioritise --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main validate --targets-file data\validation\sample_validation_targets.json --owasp-assess --json --html
```

`--owasp-assess` adds `owasp_assessment_summary`, `owasp_category_results`, `owasp_evidence_items`, and `owasp_coverage_gaps` to JSON and HTML reports.

## API

```http
GET /owasp/assessment/rules
POST /owasp/assessment/build
```

Build request:

```json
{
  "findings": [],
  "endpoint_results": [],
  "parameter_results": [],
  "safe_validation_results": [],
  "evidence_records": []
}
```

API key protection applies when configured. The build endpoint does not accept file paths and does not return raw sensitive response bodies.

## Dashboard

The OWASP Assessment dashboard shows summary cards, OWASP Coverage Matrix, OWASP Category Results, OWASP Evidence, Manual Validation Required, Coverage Gaps, and the existing OWASP indicator mapping.

Use assessment wording: Indicator, Evidence, Confidence, Manual Validation Required, and Coverage Gap.

## Limitations

- Access-control, design, authentication, integrity, logging, and exception-handling categories often require authenticated/manual validation.
- Local vulnerability intelligence depends on local inventory and metadata quality.
- Passive evidence may show indicators without proving impact.
- Assessment quality reflects coverage and evidence depth, not whether the target is safe or secure.
# Version 20.2 A04 Cryptographic Failures

`--a04-checks` adds dedicated A04 Cryptographic Failures evidence to the OWASP Assessment Engine. Evidence covers transport security indicators, cookie security evidence, sensitive data over cleartext indicators, HSTS, mixed content indicators, and TLS metadata. When `--owasp-assess` is also used, A04 evidence feeds `owasp_evidence_items` and the `A04:2025` category result.

The module is indicator-based and may require manual validation. It does not submit forms, capture credentials, store cookie values, store secrets, test weak TLS ciphers, or perform downgrade testing.

# Version 20.3 A07 Authentication Failures

`--a07-checks` adds dedicated A07 Authentication Failures evidence to the OWASP Assessment Engine. Evidence covers authentication endpoints, login workflow evidence, password reset workflow evidence, cookie/session evidence, rate-limit header indicators, protocol surface indicators, and manual validation needs. When `--owasp-assess` is also used, A07 evidence feeds `owasp_evidence_items` and the `A07:2025` category result.

The module is indicator-based and may require manual validation. It does not perform login attempts, brute force, credential stuffing, password guessing, MFA bypass testing, account creation, password reset, or form submission.

# Version 20.4 A10 Mishandling of Exceptional Conditions

`--a10-checks` adds dedicated A10 Mishandling of Exceptional Conditions evidence to the OWASP Assessment Engine. Evidence covers error-handling indicators, exception exposure evidence, verbose error evidence, framework debug indicators, database error indicators, status code patterns, sensitive error content, and fail-safe review required signals. When `--owasp-assess` is also used, A10 evidence feeds `owasp_evidence_items` and the `A10:2025` category result.

The module is observation-based and may require manual validation. It does not force application errors, send payloads, submit forms, modify server-side state, perform crash testing, or perform DoS testing.
## Version 20.5 A05 Injection

Version 20.5 adds A05 Injection candidate and reflection analysis. A05 evidence feeds `owasp_evidence_items`, `owasp_category_results` for `A05:2025`, and `owasp_assessment_summary` when `--a05-checks --owasp-assess` is used. A05 checks are candidate/indicator-based, use no exploit payloads, and require manual validation.
## Version 20.6 A01 Broken Access Control

Version 20.6 adds dedicated A01 Broken Access Control candidate evidence. When `--a01-checks` is enabled, A01 candidates feed `owasp_evidence_items`, `owasp_category_results`, and `owasp_assessment_summary` as manual-validation-required evidence.

See [OWASP_A01_BROKEN_ACCESS_CONTROL.md](OWASP_A01_BROKEN_ACCESS_CONTROL.md) for the candidate-only A01 workflow.
## Version 20.7 A03 Software Supply Chain

The OWASP Assessment Engine now consumes A03 Software Supply Chain evidence from `a03_supply_chain_evidence`. A03 category results become stronger when dependency metadata is exposed, SBOM components match local CVE/CPE intelligence, component version exposure has local vulnerability-intelligence evidence, source maps are observed, or vulnerable component evidence includes CVSS/EPSS metadata.

A03 checks are evidence-based and manual-validation oriented. They do not perform dependency confusion testing, package registry fetching, malicious package testing, package takeover simulation, CI/CD attack simulation, or exploit validation.
## Version 20.8 A08 Software or Data Integrity Failures

A08 evidence feeds the OWASP Assessment Engine when `--a08-checks` is enabled. The module classifies integrity indicators from endpoint, parameter, form, script, stylesheet, and limited HTML metadata. It covers file upload workflow indicators, import/export workflow indicators, webhook/callback integrity indicators, update workflow indicators, Subresource Integrity evidence, trusted-data boundary indicators, and deserialisation/data handling candidates.

The checks are safe and candidate-based. VulScan does not upload files, submit forms, trigger webhooks, call update endpoints, import data, generate deserialisation payloads, or perform bypass testing. Manual validation is required before treating A08 evidence as a confirmed finding.
