# OWASP Assessment Reporting

VulScan 20.9 adds a unified OWASP Assessment report for authorised, non-destructive assessment output. The report consolidates category results, evidence strength, confidence, coverage status, manual validation requirements, developer remediation guidance, coverage gaps, and limitations.

The report is not a security score and does not claim that an application is secure. The assessment quality score reflects evidence coverage, not application security.

## Report Purpose

The unified report is designed for clear review by security engineers, developers, and stakeholders. It explains what VulScan assessed, which OWASP categories have indicators, which categories require manual validation, and where coverage gaps remain.

## Executive Summary

The executive summary includes the assessed target, categories with indicators, strong and weak indicator counts, confirmed finding count when supported by evidence, manual validation requirements, coverage gaps, highest-signal categories, key limitations, and recommended next steps.

## Coverage Matrix

The A01-A10 coverage matrix uses these coverage statuses:

- `assessed`
- `partially_assessed`
- `manual_review_required`
- `not_assessed`
- `coverage_gap`

Assessment statuses include confirmed findings, strong indicators, weak indicators, informational-only evidence, no indicators observed, and not assessed.

A06 Insecure Design and A09 Security Logging & Alerting Failures default to manual review and coverage gap unless manual or operational evidence is supplied.

## Evidence Strength And Confidence

Evidence strength describes how much support the observed evidence provides:

- `confirmed_finding`
- `strong_indicator`
- `weak_indicator`
- `informational`

Confidence describes evidence reliability. Manual validation may still be required even when confidence is high.

## Manual Validation Checklist

The report includes checklist items for A01, A05, A06, A07, A08, A09, and A10. Default status is `pending`. Dashboard checklist status is local UI state unless saved separately.

## Coverage Gaps

Coverage gaps highlight missing assessment inputs such as authenticated testing, role-based access-control validation, business logic review, logging evidence, TLS metadata, SBOM, manual evidence, or source-code review.

## Developer Guidance

Developer remediation guidance is grouped by OWASP category and includes implementation hints, validation hints, and reference labels. The report avoids long copied reference text.

## Outputs

JSON reports include:

- `owasp_assessment_report`
- `owasp_assessment_summary`
- `owasp_category_results`
- `owasp_evidence_items`
- `owasp_coverage_matrix`
- `owasp_manual_validation_checklist`
- `owasp_developer_recommendations`
- `owasp_coverage_gaps`
- `owasp_markdown_report_path`

HTML reports include the OWASP executive summary, A01-A10 coverage matrix, category cards, evidence table, manual validation checklist, coverage gaps, developer guidance, and limitations.

Markdown reports are written to `reports/owasp/owasp_assessment_<timestamp>.md`.

## CLI Examples

```powershell
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --a01-checks --a02-checks --a03-checks --a04-checks --a05-checks --a07-checks --a08-checks --a10-checks --owasp-assess --owasp-report --json --html
```

```powershell
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --a01-checks --a03-checks --a05-checks --a08-checks --owasp-assess --owasp-report --json --html
```

```powershell
.\.venv311\Scripts\python.exe -m scanner.main scan --target 127.0.0.1 --vuln-intel --a03-checks --owasp-assess --owasp-report --json --html
```

## API Examples

Build a report:

```http
POST /owasp/report/build
```

```json
{
  "target": "http://127.0.0.1:8000",
  "owasp_assessment_summary": {},
  "owasp_category_results": [],
  "owasp_evidence_items": []
}
```

Download a generated Markdown report:

```http
GET /owasp/report/{report_id}/download
```

The download endpoint serves Markdown only from `reports/owasp` and blocks path traversal. API key protection applies when `VULSCAN_API_KEY` is configured.

## Dashboard Usage

Open the OWASP Assessment dashboard section to review overview, coverage matrix, evidence, manual validation checklist, developer guidance, coverage gaps, and export controls. Demo mode includes A01, A02, A03, A04, A05, A07, A08, and A10 indicators with A06 and A09 shown as manual coverage gaps.

## Limitations

Automated evidence cannot confirm business logic, access-control, authentication, integrity, or logging impact without manual validation. No indicator observed does not mean a category is secure.
