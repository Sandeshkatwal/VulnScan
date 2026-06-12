# Release Checklist

## Version 22.0 Public Beta

- [ ] Version Metadata reports `22.0.0-beta`.
- [ ] `scanner.main version`, `health`, and `diagnostics --json` pass.
- [ ] `scripts/check_no_secrets.py` passes.
- [ ] `scripts/check_demo_safety.py` passes.
- [ ] `scripts/public_beta_check.py` reports no blocking issues.
- [ ] Backend Regression Testing passes.
- [ ] Dashboard build passes.
- [ ] Known Limitations, Public Beta Notes, Verification Matrix, and Beta Testing Guide are current.
- [ ] GitHub issue templates and pull request template are present.
- [ ] Release Notes are generated under `reports/diagnostics/`.

- [ ] Backend tests pass.
- [ ] Dashboard build passes.
- [ ] Demo data safety check passes.
- [ ] Evidence redaction tests pass.
- [ ] No secrets in repository.
- [ ] README links checked.
- [ ] Screenshots updated or screenshot placeholders documented.
- [ ] Demo walkthrough tested.
- [ ] GitHub Actions pass.
- [ ] Version tag created.
- [ ] Release notes written.

## Verification Commands

```powershell
.\.venv311\Scripts\python.exe -m pytest
.\.venv311\Scripts\python.exe -m scanner.main version
.\.venv311\Scripts\python.exe -m scanner.main health
.\.venv311\Scripts\python.exe -m scanner.main diagnostics --json
.\.venv311\Scripts\python.exe scripts\check_no_secrets.py
.\.venv311\Scripts\python.exe scripts\check_demo_safety.py
.\.venv311\Scripts\python.exe scripts\verify_release.py
.\.venv311\Scripts\python.exe scripts\verify_commands.py
.\.venv311\Scripts\python.exe scripts\check_dependencies.py
.\.venv311\Scripts\python.exe scripts\public_beta_check.py
.\.venv311\Scripts\python.exe scripts\generate_release_notes.py
.\.venv311\Scripts\python.exe scripts\check_docs_links.py
cd dashboard
npm run build
```
