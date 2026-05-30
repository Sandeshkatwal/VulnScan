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

Recommended command:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check_release.ps1
```
