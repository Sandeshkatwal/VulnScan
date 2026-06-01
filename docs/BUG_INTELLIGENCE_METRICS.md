# Bug Intelligence Metrics

Version 18.9 adds local metrics for the Bug Intelligence Engine and Personal Performance Metrics dashboard.

## Purpose

Metrics help track local authorised security assessment workflow progress across Evidence Capture, Security Finding Reports, Submission and Retest Tracker, Duplicate Detection, Finding Fingerprinting, OWASP Indicator Mapping, and Safe Validation.

VulScan does not fetch external platform data, scrape browser sessions, request platform credentials, store API tokens, or submit reports automatically.

## Metrics

- Evidence records, reports created, submissions, accepted, duplicates, informative, not applicable, resolved, paid, and retests.
- Acceptance rate: accepted, resolved, and paid submissions divided by total submissions.
- Duplicate rate: duplicate submissions divided by total submissions.
- Informative rate: informative submissions divided by total submissions.
- Resolution rate: resolved and paid submissions divided by total submissions.
- Average time to report: created to submitted.
- Average time to triage: submitted to triaged.
- Average time to resolution: accepted to resolved.
- Average time to payment: accepted to paid.
- Total and average bounty by currency from local payment tracking fields.
- Program Performance by Program Scope.
- Vulnerability class metrics from report titles, evidence/fingerprint issue type, OWASP category, and saved findings.
- Monthly activity in `YYYY-MM` format.
- Outcome distribution for local submission statuses.

## Quality Score

The quality score is a local workflow indicator from 0 to 100.

Accepted findings, linked evidence, reports, notes, impact/remediation details, resolved outcomes, and passed retests increase the score. Duplicate, not applicable, and weakly documented outcomes reduce it.

Labels:

- Getting Started
- Improving
- Strong Workflow
- High Quality

The score does not guarantee acceptance, payout, platform success, or vulnerability validity.

## Date Ranges

Supported ranges:

- `all-time`
- `last-7-days`
- `last-30-days`
- `last-90-days`
- `this-year`
- `custom` with `start_date` and optional `end_date`

## CLI

```powershell
.\.venv311\Scripts\python.exe -m scanner.main metrics summary
.\.venv311\Scripts\python.exe -m scanner.main metrics summary --range last-30-days
.\.venv311\Scripts\python.exe -m scanner.main metrics programs
.\.venv311\Scripts\python.exe -m scanner.main metrics classes
.\.venv311\Scripts\python.exe -m scanner.main metrics export --format json
.\.venv311\Scripts\python.exe -m scanner.main metrics export --format csv
```

## API

All metrics endpoints use the same API key protection as the other local workflow endpoints.

```text
GET /bug-intelligence/metrics/summary
GET /bug-intelligence/metrics/programs
GET /bug-intelligence/metrics/classes
GET /bug-intelligence/metrics/monthly
GET /bug-intelligence/metrics/outcomes
GET /bug-intelligence/metrics/export
```

Query parameters:

- `range`
- `start_date`
- `end_date`
- `program_name`
- `format` for export, either `json` or `csv`

## Dashboard

The dashboard includes a Bug Intelligence `Performance Metrics` section with summary cards, date range filtering, activity trend bars, outcome distribution, Program Performance table, vulnerability class chart, retest performance, bounty totals, and quality indicators.

Demo mode clearly uses local demo data only.

## Privacy

Metrics are calculated from local VulScan SQLite data and local report metadata only. Sensitive notes are not included in exports. External dashboards, cookies, tokens, API keys, session data, and platform credentials are not accessed.
