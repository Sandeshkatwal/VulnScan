# OWASP A08 Software or Data Integrity Failures

## Purpose

Version 20.8 adds safe A08 Software or Data Integrity Failures indicator checks. The module identifies integrity indicator evidence from already available endpoint, parameter, form, script, stylesheet, and limited HTML metadata.

## Scope

The A08 engine covers:

- file upload workflow indicator discovery
- import/export workflow indicator discovery
- webhook/callback integrity indicator discovery
- update workflow indicator discovery
- Subresource Integrity evidence for observed external scripts and stylesheets
- trusted-data boundary indicator discovery
- deserialisation/data handling candidate discovery

## Safety Boundaries

VulScan does not upload files, submit forms, trigger webhooks, call update endpoints, import data, generate deserialisation payloads, or perform bypass testing. All A08 output is candidate-based and uses manual validation required wording unless manually supplied evidence is strong enough to support a confirmed finding.

## Checks Implemented

- Upload indicators: upload paths, multipart forms, file inputs, and upload-style field names.
- Import/export indicators: import, export, bulk, sync, backup, restore, download, and data workflow paths.
- Webhook/callback indicators: webhook, callback, events, notifications, integrations, OAuth callback, signature, HMAC, timestamp, state, and callback URL parameter names.
- Update indicators: update, upgrade, plugin, extension, theme, module, package, installer, and marketplace paths.
- SRI indicators: external scripts/stylesheets without integrity metadata, integrity attribute presence, missing crossorigin context, and inline script review indicators.
- Trusted-data boundary indicators: signature, checksum, hash, digest, token, nonce, payload, data, object, serialized, redirect URI, and callback URL parameter names.

## Manual Validation Workflow

Use authorised test systems and programme-approved data only.

- Upload integrity review: verify file type validation, storage isolation, malware scanning process if applicable, and authorization on uploaded files.
- Import data validation review: verify schema validation, tamper rejection, unauthorized field protection, and audit logging.
- Webhook signature review: verify signatures/HMAC, timestamp validation, replay protection, callback restrictions, and state validation.
- Update integrity review: verify signed packages, trusted source enforcement, rollback, and audit logging.
- Third-party script integrity review: verify SRI/CSP strategy and business need for third-party resources.
- Deserialisation safety review: verify untrusted serialized data is rejected or parsed only with safe parsers.

## Evidence Template

A08 evidence templates include candidate title, affected endpoint, workflow type, integrity boundary, why it may matter, safe manual validation steps, expected secure behaviour, evidence needed for confirmation, risk if confirmed, and recommendation.

## CLI Examples

```powershell
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --a08-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --a08-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main validate --targets-file data\validation\sample_validation_targets.json --a08-checks --owasp-assess --json --html
```

## API Examples

```http
GET /owasp/a08/rules
POST /owasp/a08/assess
POST /owasp/a08/manual-plan
```

`POST /owasp/a08/assess` accepts endpoint results, parameter results, form metadata, script/style metadata, and a limited HTML snippet. It does not accept arbitrary files and does not perform upload, webhook, update, or bypass testing.

## Dashboard Usage

The OWASP Assessment page includes an A08 Software/Data Integrity panel with summary cards, workflow candidates, Subresource Integrity evidence, upload/import review, webhook/callback review, manual validation checklist, and recommendations.

## Limitations

- Endpoint and parameter names are indicators, not proof of a vulnerability.
- Missing SRI is context-dependent.
- Full source map, file content, and serialized data analysis are intentionally out of scope in 20.8.
- Confirmation requires authorised manual validation and redacted evidence.

## Remediation Guidance

- Enforce file and data validation at trust boundaries.
- Require signatures/HMAC and replay protection for webhooks.
- Sign and verify update/plugin artifacts.
- Use CSP and SRI where appropriate for third-party resources.
- Avoid unsafe deserialisation of untrusted data.
- Keep audit logs for upload, import, webhook, and update workflows.
Version 20.9 reporting note: A08 evidence is consolidated into the unified OWASP Assessment report with manual validation checklist items for upload/import/webhook integrity and third-party script review.
## Business Logic Review Integration

A08 summaries can include Business Logic Review plans for import/export, webhook/callback, update, and integrity-sensitive workflows. State Transition Review and Abuse Case Checklist records are manual documentation only and do not trigger uploads, callbacks, imports, exports, or update workflows.
