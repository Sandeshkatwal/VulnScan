# Release Checklist

- [ ] `git status` clean
- [ ] Backend tests pass
- [ ] Dashboard build passes
- [ ] No `.env` committed
- [ ] No API keys committed
- [ ] No passwords committed
- [ ] No secrets in docs
- [ ] README updated
- [ ] Installation guide updated
- [ ] Safety guide updated
- [ ] Screenshots captured
- [ ] Demo mode tested
- [ ] API starts locally
- [ ] Dashboard starts locally
- [ ] Basic scan works
- [ ] JSON report generated
- [ ] HTML report generated
- [ ] Report access works
- [ ] Remediation workflow tested
- [ ] Sample Program Scope loads from `data/programs/sample_program_scope.json`
- [ ] Scope enforcement blocks an out-of-scope target
- [ ] Recon Intelligence sample command runs
- [ ] Endpoint Intelligence sample command runs
- [ ] Safe Validation sample command runs
- [ ] Evidence Capture listing works
- [ ] Security Finding Report listing works
- [ ] Duplicate Detection groups command works
- [ ] Submission and Retest Tracker commands work
- [ ] Performance Metrics summary works
- [ ] Dashboard Bug Intelligence workflow loads
- [ ] Dashboard Performance Metrics view loads
- [ ] Dashboard demo mode works
- [ ] Legacy `bug-report list` alias works
- [ ] Legacy `/bug-bounty/...` API routes are documented as aliases
- [ ] README screenshot placeholders reviewed
- [ ] `assets/screenshots/.gitkeep` present
- [ ] `assets/architecture/.gitkeep` present
- [ ] `assets/demo/.gitkeep` present
- [ ] Portfolio guide reviewed
- [ ] Interview talking points reviewed
- [ ] Limitations and roadmap reviewed

Recommended command:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check_release.ps1
```
