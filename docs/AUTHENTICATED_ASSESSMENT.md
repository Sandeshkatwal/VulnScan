# Authenticated Web Assessment

VulScan 21.0 adds the foundation for Authenticated Web Assessment. It introduces redacted Session Profiles, Authentication Context, Authenticated Scope boundaries, Auth-Required Endpoint classification, and Role/Permission Notes.

This is foundation-only. VulScan does not perform login automation, unauthorised authentication testing, automated credential testing, MFA circumvention testing, cross-account testing automation, or state-changing authenticated requests.

## Session Profile Concept

A Session Profile describes an authorised testing context:

- profile name
- target base URL
- auth type
- cookie names
- header names
- role label
- permission notes
- allowed hosts and paths
- blocked paths

Values are redacted for reports, terminal output, API responses, and dashboard display.

## Safe Redaction Model

VulScan redacts:

- cookie values as `[REDACTED]`
- bearer tokens as `Bearer [REDACTED]`
- basic auth as `Basic [REDACTED]`
- API keys as `[REDACTED]`
- JWT-like strings as `[REDACTED-JWT]`
- long random-looking strings as `[REDACTED]`

Safe fields include cookie names, header names, auth type, target host, role label, allowed paths, blocked paths, and redacted notes.

## What Is Stored

Version 21.0 prefers redacted profile values. The repository includes only `data/auth_profiles/sample_session_profile.redacted.json`.

## What Is Not Stored

Do not store real passwords, session cookies, bearer tokens, API keys, private keys, usernames tied to real people, HAR files, Burp exports, or cookie jars in the repository.

`.gitignore` blocks common local secret profile names and auth artifacts.

## Profile File Format

```json
{
  "profile_name": "Demo authenticated user",
  "target_base_url": "http://127.0.0.1:8000",
  "auth_type": "cookie",
  "cookies": {"sessionid": "[REDACTED]"},
  "headers": {"Authorization": "Bearer [REDACTED]"},
  "role_label": "standard_user",
  "permission_notes": "Demo profile only.",
  "allowed_hosts": ["127.0.0.1"],
  "allowed_paths": ["/"],
  "blocked_paths": ["/logout", "/delete", "/admin/delete", "/payment"],
  "local_only": true
}
```

## Blocked Path Model

Blocked paths override allowed paths. Default blocked keywords include logout, delete, remove, destroy, payment, checkout, transfer, admin/delete, and account/delete.

## Auth Boundary Model

Boundary checks return whether a URL is allowed by the profile, blocked by profile rules, why the decision was made, which rule matched, and the role label.

## CLI Examples

```powershell
.\.venv311\Scripts\python.exe -m scanner.main auth profiles
.\.venv311\Scripts\python.exe -m scanner.main auth show --profile-file data\auth_profiles\sample_session_profile.redacted.json
.\.venv311\Scripts\python.exe -m scanner.main auth validate --profile-file data\auth_profiles\sample_session_profile.redacted.json
.\.venv311\Scripts\python.exe -m scanner.main auth check-url --profile-file data\auth_profiles\sample_session_profile.redacted.json --url http://127.0.0.1:8000/dashboard
```

Auth-aware endpoint classification:

```powershell
.\.venv311\Scripts\python.exe -m scanner.main endpoints --urls-file data\endpoints\sample_urls.txt --auth-profile data\auth_profiles\sample_session_profile.redacted.json --classify-auth --json --html
```

## API Examples

```http
GET /auth/profiles
POST /auth/profile/validate
POST /auth/boundary/check
POST /auth/endpoints/classify
```

API key protection applies when configured. API responses return redacted summaries only.

## Dashboard Usage

Use the Authenticated Assessment section to review Session Profiles, profile detail, boundary checks, Auth-Required Endpoint classifications, and Role/Permission Notes. The dashboard does not expose raw auth headers, cookies, tokens, or passwords.

## Limitations

Authenticated Web Assessment in 21.0 is classification and context only. It does not perform authenticated crawling with live auth material, role comparison, session expiry testing, or account workflow testing.

## Future Work

Future versions can add encrypted local storage, authenticated crawl boundaries, explicit user-approved authenticated requests, and manual role comparison workflows.
