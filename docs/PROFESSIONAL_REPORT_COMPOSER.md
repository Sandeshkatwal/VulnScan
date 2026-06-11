# Professional Finding Builder and Report Composer

VulScan 21.7 adds a Professional Finding Builder and Report Composer for authorised assessment reporting. It composes Technical Findings and complete reports from Redacted Evidence, OWASP assessment results, manual observations, retest records, vulnerability intelligence, business logic reviews, access-control test plans, replay plans, and local scan outputs.

The composer does not run scans. It only prepares safe finding drafts and Markdown, HTML, and JSON report outputs from existing local data.

## Finding Model

Professional Findings include status, type, OWASP categories, affected targets, severity, confidence, evidence strength, validation status, Executive Summary, Business Impact, Technical Impact, Developer Remediation, Evidence References, Retest Status, Risk Acceptance Notes, limitations, source modules, and tags.

Finding statuses include `draft`, `ready_for_review`, `reviewed`, `accepted`, `false_positive`, `risk_accepted`, `remediated`, `retest_required`, and `closed`.

Validation statuses include `candidate`, `indicator_only`, `manual_validation_required`, `manually_verified_issue`, `manually_verified_secure`, `false_positive`, `retest_required`, `retest_passed`, and `retest_failed`.

## Wording Policy

Candidate and indicator-only findings use careful language:

- "VulScan identified a candidate requiring manual validation..."
- "This indicator suggests a possible area for review..."
- "The evidence does not confirm exploitability."

Confirmed wording is used only when `validation_status` is `manually_verified_issue` or evidence strength is `confirmed_finding`. False positives, secure validation, and retest passed findings receive separate wording so reports do not overstate risk.

## Evidence Linking

Findings link to Evidence Vault IDs through `evidence_references`. Reports do not inline unsafe raw evidence, raw passwords, raw cookies, raw bearer tokens, raw private keys, full sensitive response bodies, or exploit payloads.

Linked evidence must pass Evidence Vault export safety checks before report export. If linked evidence fails, the finding remains draft and report export is blocked.

## Risk Rating

Risk scoring returns a numeric score from 0 to 100, a severity suggestion, a confidence explanation, and a rationale. The helper considers severity, confidence, evidence strength, OWASP context, affected roles, and retest status. Low confidence constrains the score, and retest passed or false-positive states reduce active risk.

## Remediation Guidance

The remediation library maps guidance to OWASP categories:

- A01: server-side authorization, object ownership checks, deny by default, tenant isolation, role-based access controls.
- A02: hardened headers, disabled debug/default endpoints, careful CORS, reduced banners.
- A03: SBOM, component updates, reduced dependency metadata exposure, CVE monitoring.
- A04: HTTPS, HSTS, secure cookies, TLS hygiene.
- A05: parameterised queries, output encoding, allowlist validation, context-aware escaping.
- A07: hardened sessions, secure reset flows, MFA where appropriate, rate limiting.
- A08: signatures, upload/import validation, webhook replay protection, SRI/CSP.
- A10: generic user-facing errors, server-side logs, disabled debug mode.
- Business logic: server-side rule enforcement, state transition validation, audit logging, anti-replay controls.

## Retest And Risk Acceptance

Retest statuses are `not_retested`, `retest_required`, `retest_scheduled`, `retest_passed`, `retest_failed`, and `not_applicable`.

Risk Acceptance Notes are optional and include accepted by, accepted at, reason, expiry date, compensating controls, review date, and notes. Risk acceptance is reported separately from remediation and does not mean an issue is fixed.

## Report Sections

Reports include Cover Page, Safe Testing Statement, Executive Summary, Scope and Methodology, Findings Summary, Technical Findings, OWASP Mapping, Evidence Summary, Retest Summary, Risk Acceptance, and Appendices.

## Export Safety Checks

All Markdown, HTML, and JSON exports run safety checks before writing. Export is blocked if unsafe evidence is included or if secret-like values remain after redaction. Draft exports are allowed only when unsafe evidence is excluded.

Outputs are written to:

- `reports/composed/markdown/report_<timestamp>_<report_id>.md`
- `reports/composed/html/report_<timestamp>_<report_id>.html`
- `reports/composed/json/report_<timestamp>_<report_id>.json`

## CLI Examples

```powershell
.\.venv311\Scripts\python.exe -m scanner.main reports finding-from-evidence --evidence-id demo-evidence-001 --json
.\.venv311\Scripts\python.exe -m scanner.main reports finding-create --title "Missing CSP Header" --severity Low --owasp A02:2025 --summary "Content-Security-Policy header was not observed." --json
.\.venv311\Scripts\python.exe -m scanner.main reports findings
.\.venv311\Scripts\python.exe -m scanner.main reports finding-show --finding-id finding-001
.\.venv311\Scripts\python.exe -m scanner.main reports compose --title "VulScan OWASP Assessment Report" --target http://127.0.0.1:8000 --findings-file data\findings\sample_finding.json --markdown --html --json
.\.venv311\Scripts\python.exe -m scanner.main reports executive-summary --findings-file data\findings\sample_finding.json
.\.venv311\Scripts\python.exe -m scanner.main reports retest-summary --findings-file data\findings\sample_finding.json
.\.venv311\Scripts\python.exe -m scanner.main reports safety-check --findings-file data\findings\sample_finding.json
```

## API Examples

```http
POST /reports/finding/from-evidence
POST /reports/finding
GET /reports/findings
GET /reports/findings/{finding_id}
POST /reports/compose
POST /reports/export-safety-check
GET /reports/{report_id}
GET /reports/{report_id}/download
```

API key protection applies. Downloads are resolved from safe local report paths and path traversal is blocked.

## Dashboard Usage

The dashboard adds Finding Builder and Report Composer sections. Finding Builder shows draft Technical Findings, validation status, Evidence References, risk rating, remediation guidance, and retest status. Report Composer supports report setup, section review, findings selection, Executive Summary generation, export safety checks, and Safe Export for Markdown, HTML, and JSON.

## Limitations

VulScan does not mark candidate indicators as confirmed issues. Manual validation must support confirmed wording. The composer excludes unsafe evidence and does not include exploit payloads or unsafe reproduction steps.

## Future Work

Future versions can add richer report templates, report review workflows, signed final report metadata, and deeper dashboard editing for risk acceptance and retest records.

