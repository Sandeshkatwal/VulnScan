# Release Notes 19.0

Version 19.0 is a Bug Intelligence release hardening pass.

## Highlights

- Professional naming cleanup across the release-facing workflow.
- Preferred Program Scope, Recon Intelligence, Endpoint Intelligence, Safe Validation, Security Finding Report, Duplicate Detection, and Performance Metrics terminology.
- New `scope list` and `scope check` command group.
- Preferred `--scope-file` option added while retaining legacy `--bug-bounty-scope`.
- Preferred sample directories added under `data/programs`, `data/recon`, `data/endpoints`, and `data/validation`.
- Preferred API route aliases added:
  - `/program-scope/scopes`
  - `/program-scope/check`
  - `/recon`
  - `/endpoints/analyse`
  - `/safe-validation`
- Legacy `/bug-bounty/...` routes remain aliases and may be removed later.
- Dashboard API client now uses preferred routes.
- Release smoke tests added for imports, CLI help, scope commands, redaction, fingerprinting, metrics, and API key protection.

## Safety

- Scope-aware workflows continue to support scope enforcement.
- Safe Validation remains non-destructive and does not add exploitation, payload generation, SSRF testing, automated authentication-boundary checks, brute force, credential attack workflows, or destructive checks.
- Report serving remains restricted to local report files with path traversal blocking.
- API still binds to localhost by default and protected routes use API key checks when configured.

## Documentation

- Added Bug Intelligence workflow guide.
- Added command reference.
- Updated release checklist and user-facing docs to prefer professional terminology.

## Known Limitations

- Some internal module names, JSON keys, and legacy route paths still contain `bug_bounty` for compatibility.
- Security Finding Report generation remains file/report based; no external platform submission is performed.
- Performance Metrics are local workflow indicators only and do not guarantee platform success or vulnerability validity.

See [RELEASE_NOTES_19_1.md](RELEASE_NOTES_19_1.md) for final GitHub portfolio polish.
