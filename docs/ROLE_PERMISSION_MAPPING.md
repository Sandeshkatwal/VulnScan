# Role and Permission Mapping

Version 21.2 adds a safe Role and Permission Mapping assistant for A01 Access-Control Planning.

## Purpose

The assistant helps document Role Profiles, build an Access-Control Matrix, infer endpoint actions from existing endpoint metadata, and generate Manual Validation Required plans. It does not perform automatic access checks.

## Role Profiles

Role Profiles contain safe labels only:

- role name and role label
- user type
- tenant label
- linked redacted Session Profile summary
- Allowed Action and Disallowed Action notes
- Permission Notes

Do not store usernames, passwords, session cookies, bearer tokens, Authorization headers, or secret authentication material.

## Permission Matrix

The Access-Control Matrix defines Permission Actions and expected role permissions:

- `allowed`
- `denied`
- `conditional`
- `unknown`

Validation status is manual:

- `not_tested`
- `manually_verified_allowed`
- `manually_verified_denied`
- `needs_review`
- `not_applicable`

## Endpoint-To-Action Mapping

VulScan infers likely actions from existing endpoint metadata only. Examples:

- `GET /account` -> `view`
- `/admin/users` -> `manage_users`
- `/roles` -> `manage_roles`
- `/billing` -> `billing`
- `/upload` -> `upload`
- `/reports/export` -> `export`
- `/delete` -> `delete`

Inference does not make requests, submit forms, or call state-changing endpoints.

## Manual Validation Plans

Manual plans include:

- role label
- endpoint
- inferred action
- expected permission
- safe manual steps
- expected secure result
- evidence to collect
- risk if failed
- safety notes

Use Authorised Test Accounts Only. Capture redacted evidence only.

## Role Comparison Notes

Role comparison notes are manual documentation records for expected differences between roles. VulScan 21.2 does not perform automated role comparison or cross-account requests.

## Safety Model

VulScan does not:

- perform automatic elevated-access checks
- perform automated authentication-boundary checks
- perform automatic account-to-account testing
- access data outside the authorised assessment scope
- submit forms automatically
- perform state-changing requests automatically
- test delete, update, payment, or admin actions automatically
- store passwords, session cookies, bearer tokens, or Authorization headers

## CLI Examples

```powershell
.\.venv311\Scripts\python.exe -m scanner.main roles list --roles-file data\roles\sample_roles.json
.\.venv311\Scripts\python.exe -m scanner.main roles show --roles-file data\roles\sample_roles.json --role standard_user
.\.venv311\Scripts\python.exe -m scanner.main roles matrix --matrix-file data\roles\sample_permission_matrix.json
.\.venv311\Scripts\python.exe -m scanner.main roles map-endpoints --roles-file data\roles\sample_roles.json --matrix-file data\roles\sample_permission_matrix.json --endpoints-file data\endpoints\sample_urls.txt --json --html
.\.venv311\Scripts\python.exe -m scanner.main roles plan --role standard_user --endpoint "http://127.0.0.1:8000/admin/users" --expected denied
```

## API Examples

- `GET /roles`
- `POST /roles/validate`
- `POST /roles/map-endpoints`
- `POST /roles/manual-plan`

All role mapping endpoints use existing API key protection when configured and perform no live requests.

## Dashboard Usage

The dashboard includes Role & Permission Mapping under Authenticated Assessment. It shows Role Profiles, Permission Matrix, Endpoint Action Mapping, Role Endpoint Matrix, Manual Validation Plan, and Role Comparison Notes.

## Limitations

Role and Permission Mapping is planning and documentation only. Manual validation is required before reporting A01 impact.

## Future Work

Future versions may add richer local import/export and evidence management workflows while preserving the no-automatic-cross-account-testing safety boundary.

## Version 21.3 Access Control Manual Test Planner

Role and Permission Mapping outputs can now feed A01 Manual Validation Plan records for Expected Behaviour, Observed Behaviour, Evidence Checklist, and Retest Workflow documentation. See `docs/ACCESS_CONTROL_MANUAL_TEST_PLANNER.md`.
## Replay Plan Integration

Role labels and expected permissions can be used by Version 21.4 Replay Plans for role permission review. VulScan stores labels and planning metadata only. It does not perform automatic cross-account testing or automatic privilege changes.
