# Access Control Manual Test Planner

Version 21.3 adds an Access Control Manual Test Planner for authorised A01 testing workflow and documentation.

## Purpose

The planner converts A01 candidates, Role and Permission Mapping outputs, Authenticated Crawl metadata, endpoint classifications, and permission matrices into structured A01 Manual Validation Plan records. Plans capture Expected Behaviour, Observed Behaviour, Evidence Checklist status, Retest Workflow status, and report-ready A01 text.

The planner does not perform live requests.

## Manual Test Plans

Each plan includes:

- test plan ID, title, category, and test type
- target and affected endpoint
- role label, role ID, and tenant label
- expected permission and Expected Behaviour
- test preconditions and manual steps
- Evidence Checklist
- Observed Behaviour
- validation status
- Retest Workflow links
- recommendation and safety notes

## Supported Test Types

- Object Ownership Review
- Tenant Boundary Review
- Function-Level Authorization Review
- sensitive export/download review
- role permission review
- admin surface review
- custom

## Evidence Checklist

Default checklist items include scope confirmation, role label, endpoint, expected permission, Expected Behaviour, Observed Behaviour, safe status code, redacted screenshot or summary, secret-free evidence, retest requirement, and recommendation.

## Expected vs Observed Behaviour

Manual observations record:

- observed access result
- status code if safe
- redacted message summary
- evidence summary
- evidence file path under `reports/access_control_tests/evidence`
- tester notes

Do not store raw response bodies, passwords, session cookies, bearer tokens, Authorization headers, or secret authentication material.

## Retest Workflow

Retest records capture remediation summary, retest steps, observed retest result, retest status, and notes. Retest records are local documentation only.

## Report-Ready Templates

Report templates use candidate wording unless manual observation records an issue, such as `unexpectedly_allowed` or `unexpectedly_denied`. Templates include Expected Behaviour, Observed Behaviour, impact if confirmed, evidence, manual steps, recommendation, retest notes, limitations, and a safe testing statement.

## Safety Model

- Authorised Test Accounts Only.
- Manual Validation Required.
- No live requests are performed by planner commands or API endpoints.
- No form submission or state-changing action is performed.
- No account-to-account requests are performed automatically.
- Evidence must be redacted.

## CLI Examples

```powershell
.\.venv311\Scripts\python.exe -m scanner.main access-tests list --plans-file data\access_control_tests\sample_a01_test_plan.json
.\.venv311\Scripts\python.exe -m scanner.main access-tests create --role standard_user --endpoint "http://127.0.0.1:8000/admin/users" --expected denied --test-type vertical_access_control_review --json --html
.\.venv311\Scripts\python.exe -m scanner.main access-tests show --plan-id demo-plan-001 --plans-file data\access_control_tests\sample_a01_test_plan.json
.\.venv311\Scripts\python.exe -m scanner.main access-tests observe --plan-id demo-plan-001 --observed-result denied_as_expected --status-code 403 --summary "Access denied for standard_user as expected" --json
.\.venv311\Scripts\python.exe -m scanner.main access-tests report --plan-id demo-plan-001 --plans-file data\access_control_tests\sample_a01_test_plan.json --markdown
.\.venv311\Scripts\python.exe -m scanner.main access-tests retest --plan-id demo-plan-001 --status passed --notes "Access remains denied after remediation" --json
```

## API Examples

- `POST /access-tests/generate`
- `POST /access-tests/create`
- `POST /access-tests/observe`
- `POST /access-tests/retest`
- `GET /access-tests/{plan_id}`
- `POST /access-tests/report-template`

API key protection applies when configured.

## Dashboard Usage

The dashboard includes an A01 Manual Test Planner section with Test Plan Summary, Test Plan Table, Plan Detail, Evidence Checklist, Expected vs Observed, Retest Workflow, and Report Template panels.

## Limitations

The planner records workflow and evidence documentation only. Manual validation is required before reporting confirmed A01 impact.

## Future Work

Future versions can add richer local evidence attachment management and submission workflow links while preserving the manual-only safety model.
## Replay Plan Integration

Version 21.4 adds the Safe Authenticated Parameter Replay Planner. Object identifier, tenant boundary, and role/permission Replay Plans can enrich A01 manual validation records with Redacted Request Templates and Expected Behaviour/Observed Behaviour workflow data. Replay Plans do not make live requests.

## Business Logic Review Integration

Version 21.5 Business Logic Review can link access-control plans to workflow approvals, tenant boundary workflows, role-sensitive actions, and object ownership workflows. Workflow Review Plans remain Manual Validation Required records and do not perform live workflow requests.
