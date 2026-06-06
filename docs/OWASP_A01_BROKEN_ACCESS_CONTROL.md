# OWASP A01 Broken Access Control Candidate Engine

Version 20.6 adds a dedicated A01 Broken Access Control candidate engine for authorised web assessment work. It identifies access-control candidates from existing endpoint discovery, parameter intelligence, URL structures, API patterns, object identifiers, admin/function surfaces, tenant indicators, export/download workflows, and manual evidence records.

The A01 engine is candidate and planning only. It produces candidate evidence, indicator confidence, candidate scores, manual validation checklists, and report-ready templates.

It does not perform auth bypass automation, cross-account testing, credential attacks, privilege escalation attempts, destructive actions, or state-changing requests. It does not request or compare two accounts automatically and does not access unauthorised data.

## Checks Implemented

- Object-level authorization candidates: `id`, `user_id`, `account_id`, `customer_id`, `order_id`, `invoice_id`, `document_id`, `file_id`, `report_id`, and object-like path segments.
- Function-level authorization candidates: admin, management, settings, role, permission, user management, import, export, update, delete, approve, reject, enable, disable, and similar function surfaces.
- Tenant boundary candidates: tenant, organisation, organization, workspace, team, project, company, and related identifiers.
- Sensitive resource candidates: download, export, report, invoice, document, attachment, file, private media, API file, and API report endpoints.
- Role and permission indicators: role, permission, `is_admin`, access level, scope, privilege, and group parameters.
- API access-control candidates: REST object endpoints, user/account/order APIs, admin APIs, bulk APIs, and GraphQL review points.

Object identifiers in paths are normalised, for example `/users/123` becomes `/users/{id}` and UUID paths become `/users/{uuid}`. Query parameter values are not retained unnecessarily.

## Manual Validation Workflow

Generated plans include horizontal access-control review, vertical access-control review, tenant boundary review, sensitive export/download review, and function authorization review.

Manual validation must use authorised test accounts, approved test tenants, and programme-approved test data only. Do not access real user data.

## CLI Examples

```powershell
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --a01-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main web-scan --url http://127.0.0.1:8000 --crawl --headers --cookies --forms --passive-summary --a01-checks --owasp-assess --json --html
.\.venv311\Scripts\python.exe -m scanner.main validate --targets-file data\validation\sample_validation_targets.json --a01-checks --owasp-assess --json --html
```

## API Examples

`GET /owasp/a01/rules` returns local A01 rules.

`POST /owasp/a01/assess` accepts:

```json
{
  "target": "http://127.0.0.1:8000",
  "endpoint_results": [{"url": "http://127.0.0.1:8000/api/users/123"}],
  "parameter_results": [{"url": "http://127.0.0.1:8000/account?id=123", "parameter_name": "id"}],
  "evidence_records": []
}
```

`POST /owasp/a01/manual-plan` generates safe manual validation guidance and a report-ready evidence template. API key protection applies.

## Dashboard Usage

The dashboard displays A01 under OWASP Assessment when report data contains `a01_access_control_summary` and `a01_access_control_evidence`.

## Evidence Template

Each candidate includes candidate title, affected endpoint, parameter/object identifier, candidate type, why it may matter, safe manual validation steps, expected secure behaviour, evidence needed for confirmation, risk if confirmed, and recommendation.

Use “Candidate requiring manual validation” until manual evidence supports stronger language.

## Remediation Guidance

If manual validation confirms an issue, enforce server-side authorization checks for object ownership, function authorization, tenant isolation, export/download authorization, and role/permission decisions. Prefer deny-by-default authorization, centralised policy checks, scoped object queries, server-side tenant binding, and audit logging for sensitive access decisions.

## Limitations

A01 Broken Access Control frequently requires authenticated, role-aware, and tenant-aware manual validation. VulScan identifies candidates and helps plan validation; it does not confirm broken access control without manually supplied evidence.
Version 20.9 reporting note: A01 evidence is consolidated into the unified OWASP Assessment report with coverage status, evidence strength, confidence, developer remediation guidance, and manual validation checklist items for object ownership, tenant boundaries, and admin/function authorization.

Version 21.0 note: A01 can include redacted role labels and Auth-Required Endpoint classification from a Session Profile. VulScan does not compare profiles or automate cross-account testing in this version.
